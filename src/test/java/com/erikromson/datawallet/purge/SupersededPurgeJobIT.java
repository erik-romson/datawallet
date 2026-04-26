package com.erikromson.datawallet.purge;

import com.erikromson.datawallet.domain.EntryEntity;
import com.erikromson.datawallet.domain.EntryRecipientEntity;
import com.erikromson.datawallet.domain.EntryRecipientRepository;
import com.erikromson.datawallet.domain.EntryRepository;
import com.erikromson.datawallet.persistence.PostgresTestcontainer;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@ActiveProfiles({"test", "it"})
@Import(PostgresTestcontainer.class)
@TestPropertySource(properties = "datawallet.purge.enabled=true")
class SupersededPurgeJobIT {

    @Autowired private SupersededPurgeJob purgeJob;
    @Autowired private EntryRepository entryRepository;
    @Autowired private EntryRecipientRepository entryRecipientRepository;

    @Test
    void purgesSupersededEntriesOlderThan30Days() {
        UUID entryId = UUID.randomUUID();
        UUID issuerId = UUID.randomUUID();
        UUID verifierId = UUID.randomUUID();
        byte[] fakeHash = new byte[32];
        byte[] fakeKeyId = new byte[16];
        Instant oldSupersededAt = Instant.now().minus(31, ChronoUnit.DAYS);

        entryRepository.save(new EntryEntity(
                entryId, 1, issuerId, false, oldSupersededAt.minusSeconds(3600), oldSupersededAt,
                new byte[]{0x01}, fakeHash, "Issuer", fakeKeyId, "old"));
        entryRecipientRepository.save(new EntryRecipientEntity(entryId, 1, verifierId, fakeKeyId));

        purgeJob.run();

        assertThat(entryRepository.existsByEntryId(entryId)).isFalse();
        assertThat(entryRecipientRepository.existsByEntryIdAndVerifierId(entryId, verifierId)).isFalse();
    }

    @Test
    void doesNotPurgeEntriesWithin30Days() {
        UUID entryId = UUID.randomUUID();
        UUID issuerId = UUID.randomUUID();
        byte[] fakeHash = new byte[32];
        byte[] fakeKeyId = new byte[16];
        Instant recentSupersededAt = Instant.now().minus(29, ChronoUnit.DAYS);

        entryRepository.save(new EntryEntity(
                entryId, 1, issuerId, false, recentSupersededAt.minusSeconds(3600), recentSupersededAt,
                new byte[]{0x01}, fakeHash, "Issuer", fakeKeyId, "recent"));

        purgeJob.run();

        assertThat(entryRepository.existsByEntryId(entryId)).isTrue();
    }

    @Test
    void doesNotPurgeCurrentEntries() {
        UUID entryId = UUID.randomUUID();
        UUID issuerId = UUID.randomUUID();
        byte[] fakeHash = new byte[32];
        byte[] fakeKeyId = new byte[16];

        entryRepository.save(new EntryEntity(
                entryId, 1, issuerId, true, Instant.now().minus(31, ChronoUnit.DAYS), null,
                new byte[]{0x01}, fakeHash, "Issuer", fakeKeyId, "current"));

        purgeJob.run();

        assertThat(entryRepository.existsByEntryId(entryId)).isTrue();
    }
}
