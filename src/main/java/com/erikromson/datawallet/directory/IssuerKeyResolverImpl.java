package com.erikromson.datawallet.directory;

import com.erikromson.datawallet.domain.DirectoryRecordEntity;
import com.erikromson.datawallet.domain.DirectoryRecordRepository;
import com.erikromson.datawallet.envelope.DirectoryKeyView;
import com.erikromson.datawallet.envelope.IssuerKeyResolver;

import java.nio.ByteBuffer;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

public class IssuerKeyResolverImpl implements IssuerKeyResolver {

    private static final long CACHE_TTL_MS = 60_000;

    private final DirectoryRecordRepository repository;
    private final DirectoryRecordVerifier verifier;
    private final PinnedRootHolder pinnedRootHolder;
    private final Map<String, CacheEntry> cache = new ConcurrentHashMap<>();

    public IssuerKeyResolverImpl(DirectoryRecordRepository repository,
                                  DirectoryRecordVerifier verifier,
                                  PinnedRootHolder pinnedRootHolder) {
        this.repository = repository;
        this.verifier = verifier;
        this.pinnedRootHolder = pinnedRootHolder;
    }

    @Override
    public Optional<DirectoryKeyView> resolve(UUID issuerId, byte[] keyId, long atMs) {
        String cacheKey = issuerId + ":" + HexFormat.of().formatHex(keyId);

        CacheEntry cached = cache.get(cacheKey);
        if (cached != null && cached.view != null
                && System.currentTimeMillis() - cached.storedAt < CACHE_TTL_MS) {
            return filterByTime(cached.view, atMs);
        }

        DirectoryKeyView bestView = resolveOnce(issuerId, keyId);

        // If nothing verified, the in-memory pinned root may be stale (e.g. a
        // newly-published root that landed in pinned_root_history but hasn't
        // been picked up yet — the dev-mode `init-dev-trust` CLI path). Reload
        // and retry once before caching.
        if (bestView == null && pinnedRootHolder.reloadFromDbIfStale()) {
            bestView = resolveOnce(issuerId, keyId);
        }

        // Cache only successful resolutions; misses are not cached so a later
        // directory publish becomes visible immediately.
        if (bestView != null) {
            cache.put(cacheKey, new CacheEntry(bestView, System.currentTimeMillis()));
        }
        return filterByTime(bestView, atMs);
    }

    private DirectoryKeyView resolveOnce(UUID issuerId, byte[] keyId) {
        List<DirectoryRecordEntity> entities = repository.findBySubjectIdAndKeyId(issuerId, keyId);
        DirectoryKeyView bestView = null;
        for (DirectoryRecordEntity entity : entities) {
            DirectoryRecord record;
            try {
                record = verifier.verify(entity.getSignedRecord(), pinnedRootHolder.get());
            } catch (DirectoryRejection e) {
                continue;
            }
            UUID subjectId = bytesToUuid(record.subjectId());
            bestView = new DirectoryKeyView(
                    subjectId, record.keyId(), record.publicKey(),
                    record.status(), record.validFrom(), record.validUntil()
            );
        }
        return bestView;
    }

    private Optional<DirectoryKeyView> filterByTime(DirectoryKeyView view, long atMs) {
        if (view == null) {
            return Optional.empty();
        }
        if (atMs >= view.validFrom() && atMs < view.validUntil()) {
            return Optional.of(view);
        }
        return Optional.empty();
    }

    void clearCache() {
        cache.clear();
    }

    private static UUID bytesToUuid(byte[] bytes) {
        ByteBuffer buf = ByteBuffer.wrap(bytes);
        return new UUID(buf.getLong(), buf.getLong());
    }

    private record CacheEntry(DirectoryKeyView view, long storedAt) {}
}
