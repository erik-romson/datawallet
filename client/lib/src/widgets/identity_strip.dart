import 'dart:typed_data';

import 'package:flutter/material.dart';

import '../crypto/fingerprint.dart';

/// Renders the load-bearing identity for a verifier or issuer.
///
/// Per plan.md §2: the [handle] (stable ID) and [fingerprint] are the
/// authoritative identity elements. The [displayName] is advisory only
/// and MUST be rendered with a visible "presentation only" caveat to
/// prevent display-name impersonation.
class IdentityStrip extends StatelessWidget {
  /// Stable handle (e.g. "alice").
  final String handle;

  /// The public key whose fingerprint is the cryptographic identity anchor.
  final Uint8List publicKey;

  /// Optional human-readable label — never authoritative, always caveated.
  final String? displayName;

  const IdentityStrip({
    super.key,
    required this.handle,
    required this.publicKey,
    this.displayName,
  });

  @override
  Widget build(BuildContext context) {
    final fp = Fingerprint.render(publicKey);
    final theme = Theme.of(context);

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      mainAxisSize: MainAxisSize.min,
      children: [
        // Handle — stable, authoritative
        Text(
          '@$handle',
          key: const Key('identity_handle'),
          style: theme.textTheme.titleMedium
              ?.copyWith(fontWeight: FontWeight.bold),
        ),
        const SizedBox(height: 2),
        // Fingerprint — cryptographic identity anchor
        Text(
          fp,
          key: const Key('identity_fingerprint'),
          style: theme.textTheme.bodySmall?.copyWith(
            fontFamily: 'monospace',
            letterSpacing: 1.2,
          ),
        ),
        if (displayName != null) ...[
          const SizedBox(height: 2),
          Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              Text(
                displayName!,
                key: const Key('identity_display_name'),
                style: theme.textTheme.bodySmall,
              ),
              const SizedBox(width: 4),
              Container(
                padding:
                    const EdgeInsets.symmetric(horizontal: 4, vertical: 1),
                decoration: BoxDecoration(
                  border: Border.all(color: Colors.orange.shade300),
                  borderRadius: BorderRadius.circular(3),
                ),
                child: Text(
                  'presentation only',
                  key: const Key('identity_presentation_only_badge'),
                  style: theme.textTheme.labelSmall?.copyWith(
                    color: Colors.orange.shade700,
                  ),
                ),
              ),
            ],
          ),
        ],
      ],
    );
  }
}
