// The executable name is part of the public CLI.
// ignore_for_file: file_names

import 'dart:io';

import 'package:args/args.dart';
import 'package:encrypt_plus/encrypt.dart';

/// Prints cryptographically secure random bytes in base 64 or base 16.
void main(List<String> args) {
  final argParser = ArgParser()
    ..addOption(
      'length',
      abbr: 'l',
      defaultsTo: '32',
      help: 'The length of the bytes',
    )
    ..addOption(
      'base',
      abbr: 'b',
      defaultsTo: '64',
      allowed: ['64', '16'],
      help: 'Bytes represented as base 64 or base 16 (Hexdecimal)',
    )
    ..addFlag('help', abbr: 'h', negatable: false, help: 'Show this help');

  final ArgResults results;
  try {
    results = argParser.parse(args);
  } on FormatException catch (error) {
    stderr
      ..writeln(error.message)
      ..writeln(argParser.usage);
    exitCode = 64;
    return;
  }

  if (results.flag('help')) {
    stdout.writeln(argParser.usage);
    return;
  }

  final length = int.tryParse(results.option('length')!);
  if (length == null || length <= 0) {
    stderr.writeln('--length must be a positive integer');
    exitCode = 64;
    return;
  }

  final secureRandom = SecureRandom(length);
  stdout.writeln(
    results.option('base') == '16' ? secureRandom.base16 : secureRandom.base64,
  );
}
