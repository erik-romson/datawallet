package com.erikromson.datawallet.intermediate.revoke;

import com.erikromson.datawallet.intermediate.cbor.IntermediateCborMapper;
import com.erikromson.datawallet.intermediate.client.DataWalletAdminClient;
import com.erikromson.datawallet.intermediate.denylist.RevocationDenyList;
import com.erikromson.datawallet.intermediate.security.StubTriggerAuthResolver;
import com.erikromson.datawallet.intermediate.signer.DirectoryRecordSigner;
import com.erikromson.datawallet.intermediate.signer.SoftSigner;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class AccountDeletionRevokeTriggerTest {

    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();
    private static final byte[] SEED = HexFormat.of().parseHex(
            "0102030405060708091011121314151617181920212223242526272829303132");
    private static final Clock FIXED_CLOCK = Clock.fixed(Instant.parse("2026-01-15T12:00:00Z"), ZoneOffset.UTC);

    private IntermediateCborMapper cbor;
    private DirectoryRecordSigner recordSigner;
    private MockMvc mvc;
    private ObjectMapper json;
    private AtomicInteger publishCount;
    private TestDenyList denyList;
    private UUID installUuid;
    private byte[] keyId;

    @BeforeEach
    void setUp() {
        SoftSigner signer = new SoftSigner(SEED);
        cbor = new IntermediateCborMapper();
        recordSigner = new DirectoryRecordSigner(signer, cbor, FIXED_CLOCK);
        SimpleMeterRegistry meterRegistry = new SimpleMeterRegistry();

        installUuid = UUID.randomUUID();
        byte[] pubkey = new byte[32];
        keyId = DirectoryRecordSigner.computeKeyId(pubkey);
        byte[] activeRecord = recordSigner.signIssuerRecord(installUuid, pubkey, keyId, "active");

        publishCount = new AtomicInteger();
        denyList = new TestDenyList();

        DataWalletAdminClient client = new StubAdminClient(
                new DataWalletAdminClient.IssuerRecord(keyId, "active", activeRecord),
                publishCount);

        RevokeService revokeService = new RevokeService(client, recordSigner, denyList, cbor, meterRegistry);
        AccountDeletionTriggerController controller =
                new AccountDeletionTriggerController(revokeService, new StubTriggerAuthResolver());
        mvc = MockMvcBuilders.standaloneSetup(controller).build();
        json = new ObjectMapper();
    }

    @Test
    void publishesRevokedRecordAndDenylists() throws Exception {
        String body = json.writeValueAsString(Map.of(
                "install_uuid", installUuid.toString(),
                "key_id", B64URL.encodeToString(keyId),
                "reason_code", "account_deletion"
        ));

        mvc.perform(post("/revoke/trigger")
                        .header(StubTriggerAuthResolver.HEADER, StubTriggerAuthResolver.HEADER_VALUE)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.signed_record").isString());

        assertThat(publishCount.get()).isEqualTo(1);
        assertThat(denyList.insertedCount).isEqualTo(1);
    }

    @Test
    void rejectsUnauthenticatedCall() throws Exception {
        String body = json.writeValueAsString(Map.of(
                "install_uuid", installUuid.toString(),
                "key_id", B64URL.encodeToString(keyId),
                "reason_code", "account_deletion"
        ));

        mvc.perform(post("/revoke/trigger")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("trigger_auth_required"));

        assertThat(publishCount.get()).isEqualTo(0);
        assertThat(denyList.insertedCount).isEqualTo(0);
    }

    @Test
    void returns404ForUnknownInstall() throws Exception {
        DataWalletAdminClient noRecordClient = new StubAdminClient(null, new AtomicInteger());
        RevokeService service = new RevokeService(
                noRecordClient, recordSigner, denyList, cbor, new SimpleMeterRegistry());
        MockMvc localMvc = MockMvcBuilders.standaloneSetup(
                new AccountDeletionTriggerController(service, new StubTriggerAuthResolver())).build();

        String body = json.writeValueAsString(Map.of(
                "install_uuid", UUID.randomUUID().toString(),
                "key_id", B64URL.encodeToString(keyId),
                "reason_code", "account_deletion"
        ));

        localMvc.perform(post("/revoke/trigger")
                        .header(StubTriggerAuthResolver.HEADER, StubTriggerAuthResolver.HEADER_VALUE)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error").value("not_found"));
    }

    private static class StubAdminClient extends DataWalletAdminClient {
        private final DataWalletAdminClient.IssuerRecord record;
        private final AtomicInteger publishCount;

        StubAdminClient(DataWalletAdminClient.IssuerRecord record, AtomicInteger publishCount) {
            super("http://unused", java.net.http.HttpClient.newHttpClient());
            this.record = record;
            this.publishCount = publishCount;
        }

        @Override
        public void publishDirectoryRecord(byte[] signedRecordCbor) { publishCount.incrementAndGet(); }

        @Override
        public Optional<IssuerRecord> getIssuerRecord(UUID installUuid) { return Optional.ofNullable(record); }
    }

    private static class TestDenyList extends RevocationDenyList {
        int insertedCount = 0;

        TestDenyList() { super(null, new SimpleMeterRegistry(), 600); }

        @Override protected void startupRebuild() {}
        @Override public boolean isRevoked(UUID installUuid, byte[] keyId) { return false; }
        @Override public void insertEagerly(UUID installUuid, byte[] keyId) { insertedCount++; }
        @Override public int size() { return 0; }
        @Override public long ageSeconds() { return 0; }
    }
}
