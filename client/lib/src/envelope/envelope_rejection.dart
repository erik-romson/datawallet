/// Base class for all envelope verification failures.
sealed class EnvelopeRejection implements Exception {
  final String message;

  const EnvelopeRejection(this.message);

  @override
  String toString() => '$runtimeType: $message';
}

/// The CBOR bytes could not be parsed or are not in canonical form.
final class MalformedCbor extends EnvelopeRejection {
  final Object? cause;

  const MalformedCbor(String message, [this.cause]) : super(message);
}

/// The envelope version is not supported by this implementation.
final class UnsupportedVersion extends EnvelopeRejection {
  UnsupportedVersion(int version)
      : super('Unsupported envelope version: $version');
}

/// The issuer signing key was not active at [createdAt].
final class IssuerKeyNotActiveAt extends EnvelopeRejection {
  const IssuerKeyNotActiveAt(String detail) : super(detail);
}

/// The Ed25519 signature did not verify.
final class SignatureInvalid extends EnvelopeRejection {
  const SignatureInvalid() : super('Envelope signature verification failed');
}

/// The SHA-256 of the ciphertext does not match [ciphertext_hash].
final class CiphertextHashMismatch extends EnvelopeRejection {
  const CiphertextHashMismatch()
      : super('SHA-256 of ciphertext does not match ciphertext_hash');
}
