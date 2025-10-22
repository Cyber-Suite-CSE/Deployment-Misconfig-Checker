import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

export default function CvePage() {
  return (
    <div className="max-w-6xl mx-auto">
      <div className="space-y-6">
        <Card>
          <CardHeader>
            <CardTitle>CVE Vulnerability Scanner</CardTitle>
            <CardDescription>
              Check for known vulnerabilities using the Common Vulnerabilities and Exposures database
            </CardDescription>
          </CardHeader>
          <CardContent>
            <p className="text-muted-foreground">
              This scanner will identify known vulnerabilities including:
            </p>
            <ul className="list-disc list-inside mt-4 space-y-2 text-muted-foreground">
              <li>Software version vulnerabilities</li>
              <li>Zero-day exploits</li>
              <li>Critical security patches</li>
              <li>Exploitation risk assessment</li>
            </ul>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
