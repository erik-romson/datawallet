import 'dart:typed_data';

import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:sodium/sodium.dart';

import '../api/directory_client.dart';
import '../api/shared_client.dart';
import '../crypto/fingerprint.dart';
import '../directory/directory_record_codec.dart';
import '../state/session.dart';
import '../state/wallet_state.dart';
import 'shared_detail_screen.dart';

/// Paginated list of shared entries for the authenticated verifier.
///
/// Displays issuer label (advisory), issuer signing-key fingerprint
/// (computed from the directory's signed record — authoritative), and
/// description (server-visible cleartext, badged accordingly).
class SharedListScreen extends StatefulWidget {
  final SharedClient sharedClient;
  final DirectoryClient directoryClient;
  final Session session;
  final Sodium sodium;
  final WalletState walletState;

  const SharedListScreen({
    super.key,
    required this.sharedClient,
    required this.directoryClient,
    required this.session,
    required this.sodium,
    required this.walletState,
  });

  @override
  State<SharedListScreen> createState() => SharedListScreenState();
}

// State is public to allow @visibleForTesting access from widget tests.
class SharedListScreenState extends State<SharedListScreen> {
  final List<SharedListItem> _items = [];
  final _keyCache = <String, Uint8List>{}; // issuerSigningKeyIdHex → publicKey
  final _codec = DirectoryRecordCodec();

  String? _nextCursor;
  bool _loading = false;
  bool _loadingMore = false;
  String? _error;
  final _scrollCtrl = ScrollController();

  @override
  void initState() {
    super.initState();
    _scrollCtrl.addListener(_onScroll);
    _loadFirst();
  }

  @override
  void dispose() {
    _scrollCtrl.dispose();
    super.dispose();
  }

  void _onScroll() {
    if (_scrollCtrl.position.pixels >=
            _scrollCtrl.position.maxScrollExtent - 200 &&
        _nextCursor != null &&
        !_loadingMore) {
      _loadMore();
    }
  }

  Future<void> _loadFirst() async {
    setState(() {
      _loading = true;
      _error = null;
    });
    try {
      final resp = await widget.sharedClient.listShared(widget.session.token);
      await _resolveFingerprints(resp.items);
      if (!mounted) return;
      setState(() {
        _items.addAll(resp.items);
        _nextCursor = resp.nextCursor;
        _loading = false;
      });
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _loading = false;
        _error = 'Failed to load entries: $e';
      });
    }
  }

  /// Triggers loading the next page. Exposed for widget tests.
  @visibleForTesting
  Future<void> loadMoreForTest() => _loadMore();

  Future<void> _loadMore() async {
    if (_nextCursor == null) return;
    setState(() => _loadingMore = true);
    try {
      final resp = await widget.sharedClient.listShared(
        widget.session.token,
        cursor: _nextCursor,
      );
      await _resolveFingerprints(resp.items);
      if (!mounted) return;
      setState(() {
        _items.addAll(resp.items);
        _nextCursor = resp.nextCursor;
        _loadingMore = false;
      });
    } catch (e) {
      if (!mounted) return;
      setState(() => _loadingMore = false);
    }
  }

  /// Pre-fetches directory records for issuers not already in [_keyCache].
  Future<void> _resolveFingerprints(List<SharedListItem> items) async {
    final unseenIssuers = <String>{};
    for (final item in items) {
      final hex = _hex(item.issuerSigningKeyId);
      if (!_keyCache.containsKey(hex)) {
        unseenIssuers.add(item.issuerId);
      }
    }
    for (final issuerId in unseenIssuers) {
      try {
        final wrappers =
            await widget.directoryClient.getIssuerDirectory(issuerId);
        for (final w in wrappers) {
          try {
            final rec = _codec.decode(w.signedRecord);
            _keyCache[_hex(rec.keyId)] = rec.publicKey;
          } catch (_) {}
        }
      } catch (_) {}
    }
  }

  String? _fingerprintFor(SharedListItem item) {
    final pk = _keyCache[_hex(item.issuerSigningKeyId)];
    return pk == null ? null : Fingerprint.render(pk);
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Shared with me'),
        actions: [
          IconButton(
            icon: const Icon(Icons.logout),
            tooltip: 'Log out',
            onPressed: () => widget.walletState.clearSession(),
          ),
        ],
      ),
      body: _buildBody(),
    );
  }

  Widget _buildBody() {
    if (_loading) {
      return const Center(child: CircularProgressIndicator());
    }
    if (_error != null) {
      return Center(
        child: Text(_error!, key: const Key('list_error')),
      );
    }
    if (_items.isEmpty) {
      return const Center(
        child: Text('No entries shared with you yet.'),
      );
    }
    return ListView.builder(
      controller: _scrollCtrl,
      itemCount: _items.length + (_loadingMore ? 1 : 0),
      itemBuilder: (context, i) {
        if (i == _items.length) {
          return const Padding(
            padding: EdgeInsets.all(16),
            child: Center(child: CircularProgressIndicator()),
          );
        }
        final item = _items[i];
        final fp = _fingerprintFor(item);
        return _EntryTile(
          item: item,
          fingerprint: fp,
          onTap: () => _openDetail(item.entryId),
        );
      },
    );
  }

  void _openDetail(String entryId) {
    widget.walletState.resetIdle();
    Navigator.of(context).push(MaterialPageRoute(
      builder: (_) => SharedDetailScreen(
        sharedClient: widget.sharedClient,
        directoryClient: widget.directoryClient,
        session: widget.session,
        sodium: widget.sodium,
        entryId: entryId,
      ),
    ));
  }
}

class _EntryTile extends StatelessWidget {
  final SharedListItem item;
  final String? fingerprint;
  final VoidCallback onTap;

  const _EntryTile({
    required this.item,
    required this.fingerprint,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return ListTile(
      key: Key('entry_tile_${item.entryId}'),
      onTap: onTap,
      title: Text(
        item.issuerLabel.isNotEmpty ? item.issuerLabel : item.issuerId,
        key: Key('issuer_label_${item.entryId}'),
      ),
      subtitle: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          if (fingerprint != null)
            Text(
              fingerprint!,
              key: Key('issuer_fp_${item.entryId}'),
              style: theme.textTheme.bodySmall?.copyWith(
                fontFamily: 'monospace',
                letterSpacing: 1.0,
              ),
            ),
          Row(
            children: [
              Expanded(
                child: Text(
                  item.description,
                  key: Key('description_${item.entryId}'),
                ),
              ),
              Container(
                margin: const EdgeInsets.only(left: 4),
                padding: const EdgeInsets.symmetric(horizontal: 4, vertical: 1),
                decoration: BoxDecoration(
                  border: Border.all(color: Colors.orange.shade300),
                  borderRadius: BorderRadius.circular(3),
                ),
                child: Text(
                  'server-visible',
                  style: theme.textTheme.labelSmall
                      ?.copyWith(color: Colors.orange.shade700),
                ),
              ),
            ],
          ),
        ],
      ),
    );
  }
}

String _hex(Uint8List bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
