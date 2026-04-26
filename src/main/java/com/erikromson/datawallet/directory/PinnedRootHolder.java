package com.erikromson.datawallet.directory;

import com.erikromson.datawallet.domain.PinnedRootHistoryRepository;

import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Thread-safe holder for the currently-active {@link PinnedRoot}.
 * Updated in-memory when an admin publishes a {@code RootUpdate}; also persisted to DB.
 *
 * <p>Also supports on-demand refresh from {@code pinned_root_history} via
 * {@link #reloadFromDbIfStale}, so a freshly-inserted root (e.g. via the
 * dev-mode {@code init-dev-trust} CLI command, which writes directly to the DB)
 * is picked up without restarting the server. Refresh is rate-limited so a
 * burst of failed verifications doesn't hammer the DB.
 */
public class PinnedRootHolder {

    private static final long MIN_REFRESH_INTERVAL_MS = 1_000;

    private final AtomicReference<PinnedRoot> current;
    private final AtomicLong lastRefreshAt = new AtomicLong(0);
    private volatile PinnedRootHistoryRepository repository;
    private volatile DirectoryRecordCodec codec;

    public PinnedRootHolder(PinnedRoot initial) {
        this.current = new AtomicReference<>(initial);
    }

    public PinnedRoot get() {
        return current.get();
    }

    public void update(PinnedRoot newRoot) {
        current.set(newRoot);
    }

    /// Wires the DB-backed reload source. Called once from {@link DirectoryConfig}.
    public void setReloadSource(PinnedRootHistoryRepository repository, DirectoryRecordCodec codec) {
        this.repository = repository;
        this.codec = codec;
    }

    /// Re-reads the latest pinned root from {@code pinned_root_history} if more
    /// than {@value MIN_REFRESH_INTERVAL_MS} ms have elapsed since the last
    /// refresh, replacing the in-memory copy. Returns true if a refresh happened.
    public boolean reloadFromDbIfStale() {
        if (repository == null || codec == null) return false;
        long now = System.currentTimeMillis();
        long last = lastRefreshAt.get();
        if (now - last < MIN_REFRESH_INTERVAL_MS) return false;
        if (!lastRefreshAt.compareAndSet(last, now)) return false;
        repository.findTopByOrderByIdDesc().ifPresent(entity -> {
            PinnedRoot reloaded = codec.decodePinnedRoot(entity.getPinnedRootCbor());
            current.set(reloaded);
        });
        return true;
    }
}
