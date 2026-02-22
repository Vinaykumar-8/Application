enum FileCategory {
  programming,
  document,
  executable,
  archive,
  unknown,
}

enum RiskLevel {
  low,
  medium,
  high,
}

class ClassificationResult {
  final FileCategory category;
  final RiskLevel riskLevel;
  final String reason;

  ClassificationResult({
    required this.category,
    required this.riskLevel,
    required this.reason,
  });
}
