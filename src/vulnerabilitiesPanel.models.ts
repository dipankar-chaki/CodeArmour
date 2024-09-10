export type VulnerabilityType = {
  functionName: string;
  line: number;
  title: string;
  description: string;
  cweId?: string;
  generatedDesc?: string;
  ignored?: boolean;
};

export type VulnerableFileType = {
  name: string;
  vulnerabilities: VulnerabilityType[];
} | undefined;
