import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

export default function MisconfigPage() {
  return (
    <div className="max-w-6xl mx-auto">
      <div className="space-y-6">
        <Card>
          <CardHeader>
            <CardTitle>Misconfiguration Checker</CardTitle>
            <CardDescription>
              Scan for common security misconfigurations in web applications and servers
            </CardDescription>
          </CardHeader>
          <CardContent>
            <p className="text-muted-foreground">
              This tool will help you identify security misconfigurations such as:
            </p>
            <ul className="list-disc list-inside mt-4 space-y-2 text-muted-foreground">
              <li>Exposed sensitive files and directories</li>
              <li>Weak permissions on critical resources</li>
              <li>Misconfigured security headers</li>
              <li>Default credentials and settings</li>
            </ul>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
