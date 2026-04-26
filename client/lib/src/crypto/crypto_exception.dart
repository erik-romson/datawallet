/// Thrown when a cryptographic operation fails (e.g. authentication tag mismatch).
class CryptoException implements Exception {
  final String message;
  final Object? cause;

  const CryptoException(this.message, [this.cause]);

  @override
  String toString() => cause != null
      ? 'CryptoException: $message (cause: $cause)'
      : 'CryptoException: $message';
}
