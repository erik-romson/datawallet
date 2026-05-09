package com.erikromson.datawallet.intermediate.signer;

import com.erikromson.datawallet.intermediate.cbor.IntermediateCborMapper;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HexFormat;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class DirectoryRecordSignerTest {

    private static final byte[] SEED = HexFormat.of().parseHex(
            "0102030405060708091011121314151617181920212223242526272829303132");
    private static final Clock FIXED_CLOCK = Clock.fixed(Instant.parse("2026-01-15T12:00:00Z"), ZoneOffset.UTC);

    @Test
    void signIssuerRecordProducesValidCbor() {
        SoftSigner signer = new SoftSigner(SEED);
        IntermediateCborMapper cbor = new IntermediateCborMapper();
        DirectoryRecordSigner recordSigner = new DirectoryRecordSigner(signer, cbor, FIXED_CLOCK);

        UUID installUuid = UUID.fromString("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");
        byte[] pubkey = new byte[32];
        byte[] keyId = DirectoryRecordSigner.computeKeyId(pubkey);

        byte[] signed = recordSigner.signIssuerRecord(installUuid, pubkey, keyId, "active");

        @SuppressWarnings("unchecked")
        Map<String, Object> map = cbor.readValue(signed, Map.class);
        assertThat(map.get("version")).isEqualTo(1);
        assertThat(map.get("record_type")).isEqualTo("issuer");
        assertThat(map.get("status")).isEqualTo("active");
        assertThat(map.get("key_use")).isEqualTo("sign");
        assertThat(map.get("parent_key_id")).isEqualTo(signer.keyId());
        assertThat(map.get("parent_signature")).isNotNull();
        assertThat((byte[]) map.get("parent_signature")).hasSize(64);
    }

    @Test
    void signRevokedRecordProducesRevokedStatus() {
        SoftSigner signer = new SoftSigner(SEED);
        IntermediateCborMapper cbor = new IntermediateCborMapper();
        DirectoryRecordSigner recordSigner = new DirectoryRecordSigner(signer, cbor, FIXED_CLOCK);

        UUID installUuid = UUID.fromString("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");
        byte[] pubkey = new byte[32];
        byte[] keyId = DirectoryRecordSigner.computeKeyId(pubkey);

        byte[] signed = recordSigner.signRevokedRecord(installUuid, pubkey, keyId, 1000L, 2000L);

        @SuppressWarnings("unchecked")
        Map<String, Object> map = cbor.readValue(signed, Map.class);
        assertThat(map.get("status")).isEqualTo("revoked");
        assertThat(((Number) map.get("valid_from")).longValue()).isEqualTo(1000L);
        assertThat(((Number) map.get("valid_until")).longValue()).isEqualTo(2000L);
    }
}
