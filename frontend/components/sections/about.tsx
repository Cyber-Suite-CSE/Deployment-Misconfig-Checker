"use client"

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Info, Github, Globe } from "lucide-react"

export function About() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold text-foreground mb-2">About SecSuite</h1>
        <p className="text-muted-foreground">Professional Offensive Security Tool Suite</p>
      </div>

      {/* About Card */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Info size={20} className="text-accent" />
            About This Application
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div>
            <h3 className="font-semibold mb-2">SecSuite v1.0.0</h3>
            <p className="text-sm text-muted-foreground mb-4">
              A comprehensive offensive security tool suite designed for penetration testers, security researchers, and
              red teams. SecSuite provides integrated scanning capabilities for web applications, APIs, databases, and
              source code.
            </p>
          </div>

          <div>
            <h3 className="font-semibold mb-2">Features</h3>
            <ul className="text-sm text-muted-foreground space-y-1 list-disc list-inside">
              <li>Web Domain Scanner & Service Discovery</li>
              <li>CVE Vulnerability Database</li>
              <li>Database Service Detection</li>
              <li>API Endpoint Discovery (Kethaka)</li>
              <li>Source Code Analysis</li>
              <li>Real-time Monitoring & Reporting</li>
            </ul>
          </div>
        </CardContent>
      </Card>

      {/* Technology Stack */}
      <Card>
        <CardHeader>
          <CardTitle>Technology Stack</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
            {["Next.js 15", "React 19", "TypeScript", "Tailwind CSS", "shadcn/ui", "Lucide Icons"].map((tech) => (
              <Badge key={tech} variant="secondary" className="justify-center py-2">
                {tech}
              </Badge>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Links */}
      <Card>
        <CardHeader>
          <CardTitle>Resources</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <a
            href="#"
            className="flex items-center gap-2 p-3 rounded-lg border border-border hover:bg-muted transition-colors"
          >
            <Github size={18} className="text-accent" />
            <div>
              <p className="font-medium text-sm">GitHub Repository</p>
              <p className="text-xs text-muted-foreground">View source code</p>
            </div>
          </a>
          <a
            href="#"
            className="flex items-center gap-2 p-3 rounded-lg border border-border hover:bg-muted transition-colors"
          >
            <Globe size={18} className="text-accent" />
            <div>
              <p className="font-medium text-sm">Documentation</p>
              <p className="text-xs text-muted-foreground">Learn more about features</p>
            </div>
          </a>
        </CardContent>
      </Card>

      {/* License */}
      <Card>
        <CardHeader>
          <CardTitle>License</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-muted-foreground">
            © 2025 SecSuite. All rights reserved. This tool is intended for authorized security testing only.
          </p>
        </CardContent>
      </Card>
    </div>
  )
}
