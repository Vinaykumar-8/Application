class FileClassifier {
  static const List<String> programmingExtensions = [
    'py', 'js', 'cpp', 'c', 'java', 'dart', 'sh', 'bat', 'ps1'
  ];

  static const List<String> documentExtensions = [
    'pdf', 'doc', 'docx', 'txt'
  ];

  static const List<String> executableExtensions = [
    'exe', 'apk', 'dll', 'so'
  ];

  static const List<String> archiveExtensions = [
    'zip', 'rar', '7z'
  ];
}

static ClassificationResult classify(String fileName){
  final parts = fileName.toLowerCase().split('.');

  if(parts.length<2){
    return ClassificationResult(
      category: FileCategory.unknown,
      riskLevel: RiskLevel.medium,
      reason: "No extension detected",
    );
  }

  final extension = parts.last;
  
  if(parts.length>2){
    final secondLast = parts[parts.length - 2];
    if(executableExtensions.contains(extension)){
      return ClassificationResult(
        category: FileCategory.executable,
        riskLevel: RiskLevel.high,
        reason: "Possible double extension trick",
      );
    }
  }

  if(programmingExtensions.contains(extension)){
    return ClassificationResult(
      category: FileCategory.programming,
      riskLevel: RiskLevel.high,
      reason: "Programming File - mandatory neutraization",
    );
  }

  if(documentExtensions.contains(extension)){
    return ClassificationResult(
      category: FileCategory.document,
      riskLevel: RiskLevel.medium,
      reason: "Document file - requires heuristic check",
    );
  }

  if(archiveExtensions.contains(extension)){
    return ClassificationResult(
      category: FileCategory.archive,
      riskLevel: RiskLevel.high,
      reason: "Archive may contain nested executable",
    );
  }

  return ClassificationResult(
    category: FileCategory.unknown,
    riskLevel: RiskLevel.medium,
    reason: "Unknown file type",
  );
}
