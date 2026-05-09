package com.erikromson.datawallet.intermediate.cbor;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.fasterxml.jackson.dataformat.cbor.CBORGenerator;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

public final class IntermediateCborMapper {

    static final Comparator<String> CANONICAL_KEY_ORDER = (a, b) -> {
        byte[] aEnc = encodeCborTstr(a);
        byte[] bEnc = encodeCborTstr(b);
        return Arrays.compareUnsigned(aEnc, bEnc);
    };

    private final CBORFactory factory;
    private final ObjectMapper reader;

    public IntermediateCborMapper() {
        this.factory = CBORFactory.builder()
                .disable(CBORGenerator.Feature.WRITE_TYPE_HEADER)
                .enable(CBORGenerator.Feature.WRITE_MINIMAL_INTS)
                .build();
        this.reader = new ObjectMapper(this.factory);
    }

    public byte[] writeBytes(Object value) {
        try {
            Object generic = reader.convertValue(value, Object.class);
            Object sorted = sortKeys(generic);
            return writeCanonical(sorted);
        } catch (Exception e) {
            throw new CborException("Failed to write canonical CBOR", e);
        }
    }

    @SuppressWarnings("unchecked")
    public <T> T readValue(byte[] bytes, Class<T> type) {
        try {
            return reader.readValue(bytes, type);
        } catch (Exception e) {
            throw new CborException("Failed to read CBOR", e);
        }
    }

    private byte[] writeCanonical(Object value) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (CBORGenerator gen = (CBORGenerator) factory.createGenerator(baos)) {
            writeValue(gen, value);
        }
        return baos.toByteArray();
    }

    @SuppressWarnings("unchecked")
    private void writeValue(CBORGenerator gen, Object value) throws IOException {
        switch (value) {
            case null -> gen.writeNull();
            case Map<?, ?> map -> {
                gen.writeStartObject(map.size());
                for (var entry : map.entrySet()) {
                    gen.writeFieldName((String) entry.getKey());
                    writeValue(gen, entry.getValue());
                }
                gen.writeEndObject();
            }
            case List<?> list -> {
                gen.writeStartArray(null, list.size());
                for (Object item : list) {
                    writeValue(gen, item);
                }
                gen.writeEndArray();
            }
            case byte[] bytes -> gen.writeBinary(bytes);
            case String s -> gen.writeString(s);
            case Integer i -> gen.writeNumber(i);
            case Long l -> gen.writeNumber(l);
            case Boolean b -> gen.writeBoolean(b);
            case Double d -> gen.writeNumber(d);
            case Float f -> gen.writeNumber(f);
            default -> throw new CborException("Unsupported type: " + value.getClass().getName());
        }
    }

    @SuppressWarnings("unchecked")
    private Object sortKeys(Object value) {
        if (value instanceof Map<?, ?> map) {
            TreeMap<String, Object> sorted = new TreeMap<>(CANONICAL_KEY_ORDER);
            for (var entry : map.entrySet()) {
                sorted.put((String) entry.getKey(), sortKeys(entry.getValue()));
            }
            return sorted;
        }
        if (value instanceof List<?> list) {
            return list.stream().map(this::sortKeys).toList();
        }
        return value;
    }

    static byte[] encodeCborTstr(String key) {
        byte[] utf8 = key.getBytes(StandardCharsets.UTF_8);
        int len = utf8.length;
        byte[] header;
        if (len <= 23) {
            header = new byte[]{(byte) (0x60 + len)};
        } else if (len <= 255) {
            header = new byte[]{0x78, (byte) len};
        } else if (len <= 65535) {
            header = new byte[]{0x79, (byte) (len >> 8), (byte) len};
        } else {
            header = new byte[]{0x7A, (byte) (len >> 24), (byte) (len >> 16), (byte) (len >> 8), (byte) len};
        }
        byte[] result = new byte[header.length + utf8.length];
        System.arraycopy(header, 0, result, 0, header.length);
        System.arraycopy(utf8, 0, result, header.length, utf8.length);
        return result;
    }

    public static final class CborException extends RuntimeException {
        public CborException(String message) { super(message); }
        public CborException(String message, Throwable cause) { super(message, cause); }
    }
}
