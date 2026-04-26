package com.erikromson.datawallet.directory;

public record RootSignature(byte[] rootKeyId, byte[] signature) {}
