package com.erikromson.datawallet.api.verifier;

import com.erikromson.datawallet.domain.VerifierEntity;
import com.erikromson.datawallet.domain.VerifierRepository;
import com.erikromson.datawallet.persistence.PostgresTestcontainer;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@SpringBootTest
@ActiveProfiles("test")
@Import(PostgresTestcontainer.class)
@Transactional
class VerifierDiscoveryRepositoryIT {

    @Autowired
    private VerifierRepository repo;

    @PersistenceContext
    private EntityManager em;

    private VerifierEntity makeVerifier(String handle, String displayName, boolean discoverable, String status) {
        var e = new VerifierEntity(
                UUID.randomUUID(), handle, displayName,
                new byte[32], new byte[16], new byte[32], new byte[16],
                new byte[48], new byte[48], new byte[16],
                Map.of("alg", "argon2id", "m", 268_435_456, "t", 3, "p", 1, "version", 19),
                status
        );
        e.setDiscoverable(discoverable);
        return e;
    }

    private void forceCreatedAt(UUID verifierId, Instant ts) {
        em.createNativeQuery("UPDATE verifiers SET created_at = :ts WHERE verifier_id = :id")
                .setParameter("ts", Timestamp.from(ts))
                .setParameter("id", verifierId)
                .executeUpdate();
        em.flush();
        em.clear();
    }

    @Test
    void excludesInactiveAndNonDiscoverableRows() {
        var active = makeVerifier("disc-active-" + System.nanoTime(), "Alice Active", true, "active");
        var inactive = makeVerifier("disc-inactive-" + System.nanoTime(), "Bob Inactive", true, "inactive");
        var hidden = makeVerifier("non-disc-" + System.nanoTime(), "Carol Hidden", false, "active");

        repo.saveAndFlush(active);
        repo.saveAndFlush(inactive);
        repo.saveAndFlush(hidden);

        List<VerifierEntity> result = repo.findDiscoverable(100);

        var ids = result.stream().map(VerifierEntity::getVerifierId).toList();
        assertThat(ids).contains(active.getVerifierId());
        assertThat(ids).doesNotContain(inactive.getVerifierId(), hidden.getVerifierId());
    }

    @Test
    void limitIsRespectedAndOrderIsCreatedAtDesc() {
        Instant base = Instant.now();

        var oldest = makeVerifier("ord-a-" + System.nanoTime(), "A", true, "active");
        var middle = makeVerifier("ord-b-" + System.nanoTime(), "B", true, "active");
        var newest = makeVerifier("ord-c-" + System.nanoTime(), "C", true, "active");

        repo.saveAndFlush(oldest);
        forceCreatedAt(oldest.getVerifierId(), base.minusSeconds(2));
        repo.saveAndFlush(middle);
        forceCreatedAt(middle.getVerifierId(), base.minusSeconds(1));
        repo.saveAndFlush(newest);
        forceCreatedAt(newest.getVerifierId(), base);

        // limit=2 → only the two newest
        var page = repo.findDiscoverable(2);
        assertThat(page).hasSize(2);
        assertThat(page.get(0).getVerifierId()).isEqualTo(newest.getVerifierId());
        assertThat(page.get(1).getVerifierId()).isEqualTo(middle.getVerifierId());
    }

    @Test
    void findDiscoverableSinceExcludesOlderRows() {
        Instant base = Instant.now();

        var stale = makeVerifier("since-old-" + System.nanoTime(), "Old", true, "active");
        var fresh = makeVerifier("since-new-" + System.nanoTime(), "New", true, "active");

        repo.saveAndFlush(stale);
        forceCreatedAt(stale.getVerifierId(), base.minusSeconds(10));
        repo.saveAndFlush(fresh);
        forceCreatedAt(fresh.getVerifierId(), base.minusSeconds(1));

        var result = repo.findDiscoverableSince(base.minusSeconds(5), 100);

        var ids = result.stream().map(VerifierEntity::getVerifierId).toList();
        assertThat(ids).contains(fresh.getVerifierId());
        assertThat(ids).doesNotContain(stale.getVerifierId());
    }

    @Test
    void findDiscoverableWithCursorDeliversNextPage() {
        Instant base = Instant.now();

        var oldest = makeVerifier("cur-a-" + System.nanoTime(), "A", true, "active");
        var middle = makeVerifier("cur-b-" + System.nanoTime(), "B", true, "active");
        var newest = makeVerifier("cur-c-" + System.nanoTime(), "C", true, "active");

        repo.saveAndFlush(oldest);
        forceCreatedAt(oldest.getVerifierId(), base.minusSeconds(2));
        repo.saveAndFlush(middle);
        forceCreatedAt(middle.getVerifierId(), base.minusSeconds(1));
        repo.saveAndFlush(newest);
        forceCreatedAt(newest.getVerifierId(), base);

        // page 1: newest first, limit 2
        var page1 = repo.findDiscoverable(2);
        assertThat(page1).hasSize(2);
        assertThat(page1.get(0).getVerifierId()).isEqualTo(newest.getVerifierId());

        // cursor from last row of page 1 = middle
        var cursorRow = page1.get(1);
        var page2 = repo.findDiscoverableWithCursor(cursorRow.getCreatedAt(), cursorRow.getVerifierId(), 10);

        var ids = page2.stream().map(VerifierEntity::getVerifierId).toList();
        assertThat(ids).contains(oldest.getVerifierId());
        assertThat(ids).doesNotContain(newest.getVerifierId(), middle.getVerifierId());
    }

    @Test
    void checkConstraintRejectsDiscoverableWithNullDisplayName() {
        var e = makeVerifier("chk-" + System.nanoTime(), null, true, "active");
        assertThatThrownBy(() -> repo.saveAndFlush(e))
                .isInstanceOf(DataIntegrityViolationException.class);
    }
}
