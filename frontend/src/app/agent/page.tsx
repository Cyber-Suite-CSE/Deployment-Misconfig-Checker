import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

export default function AgentPage() {
  return (
    <div className="max-w-6xl mx-auto">
      <div className="space-y-6">
        <Card>
          <CardHeader>
            <CardTitle>Agentic Workflow</CardTitle>
            <CardDescription>
              Automated security assessment combining multiple scanning techniques
            </CardDescription>
          </CardHeader>
          <CardContent>
            <p className="text-muted-foreground">
              This intelligent agent will perform comprehensive security analysis by:
            </p>
            <ul className="list-disc list-inside mt-4 space-y-2 text-muted-foreground">
              <li>Running misconfiguration and CVE scans simultaneously</li>
              <li>Correlating findings across different security domains</li>
              <li>Providing prioritized remediation recommendations</li>
              <li>Generating detailed security reports</li>
            </ul>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
