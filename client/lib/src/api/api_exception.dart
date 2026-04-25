/// Thrown when an HTTP API call returns a non-2xx status code.
class ApiException implements Exception {
  final int statusCode;
  final String? errorCode;
  final String message;

  const ApiException(this.statusCode, this.message, {this.errorCode});

  @override
  String toString() => 'ApiException($statusCode): $message';
}
