package com.erikromson.datawallet.intermediate.revoke;

import com.erikromson.datawallet.intermediate.security.StubOperatorPrincipalResolver;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.util.Base64;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class RevokeControllerTest {

    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();

    private RevokeService revokeService;
    private MockMvc mvc;
    private ObjectMapper json;

    @BeforeEach
    void setUp() {
        revokeService = mock(RevokeService.class);
        StubOperatorPrincipalResolver resolver = new StubOperatorPrincipalResolver();
        RevokeController controller = new RevokeController(revokeService, resolver);
        mvc = MockMvcBuilders.standaloneSetup(controller).build();
        json = new ObjectMapper();
    }

    @Test
    void requiresOperatorClientCert() throws Exception {
        UUID installUuid = UUID.randomUUID();
        String body = json.writeValueAsString(Map.of(
                "install_uuid", installUuid.toString(),
                "key_id", B64URL.encodeToString(new byte[16]),
                "reason_code", "lost_device"
        ));

        mvc.perform(post("/revoke").contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("operator_cert_required"));

        verify(revokeService, never()).revoke(any(), any());
    }

    @Test
    void revokesActiveInstall() throws Exception {
        UUID installUuid = UUID.randomUUID();
        byte[] keyId = new byte[16];
        byte[] revokedRecord = new byte[]{0x01, 0x02, 0x03};
        when(revokeService.revoke(any(), any())).thenReturn(revokedRecord);

        String body = json.writeValueAsString(Map.of(
                "install_uuid", installUuid.toString(),
                "key_id", B64URL.encodeToString(keyId),
                "reason_code", "lost_device"
        ));

        String expectedB64 = B64URL.encodeToString(revokedRecord);

        mvc.perform(post("/revoke")
                        .header(StubOperatorPrincipalResolver.HEADER, StubOperatorPrincipalResolver.HEADER_VALUE)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.signed_record").value(expectedB64));

        verify(revokeService).revoke(any(), any());
    }

    @Test
    void returns404ForUnknownInstall() throws Exception {
        UUID installUuid = UUID.randomUUID();
        when(revokeService.revoke(any(), any()))
                .thenThrow(new RevokeService.InstallNotFound("not found"));

        String body = json.writeValueAsString(Map.of(
                "install_uuid", installUuid.toString(),
                "key_id", B64URL.encodeToString(new byte[16]),
                "reason_code", "lost_device"
        ));

        mvc.perform(post("/revoke")
                        .header(StubOperatorPrincipalResolver.HEADER, StubOperatorPrincipalResolver.HEADER_VALUE)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error").value("not_found"));
    }

    @Test
    void publishFailureReturns502AndDoesNotMarkLocally() throws Exception {
        UUID installUuid = UUID.randomUUID();
        when(revokeService.revoke(any(), any()))
                .thenThrow(new RevokeService.RevokePublishFailed("upstream timeout"));

        String body = json.writeValueAsString(Map.of(
                "install_uuid", installUuid.toString(),
                "key_id", B64URL.encodeToString(new byte[16]),
                "reason_code", "lost_device"
        ));

        mvc.perform(post("/revoke")
                        .header(StubOperatorPrincipalResolver.HEADER, StubOperatorPrincipalResolver.HEADER_VALUE)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isBadGateway())
                .andExpect(jsonPath("$.error").value("revoke_publish_failed"))
                .andExpect(jsonPath("$.retryable").value(true));
    }

    @Test
    void stubResolverRejectsUnauthenticatedRequest() {
        StubOperatorPrincipalResolver resolver = new StubOperatorPrincipalResolver();
        MockHttpServletRequest req = new MockHttpServletRequest();
        assertThat(resolver.resolve(req)).isEmpty();
        req.addHeader(StubOperatorPrincipalResolver.HEADER, StubOperatorPrincipalResolver.HEADER_VALUE);
        assertThat(resolver.resolve(req)).contains("test-operator");
    }
}
