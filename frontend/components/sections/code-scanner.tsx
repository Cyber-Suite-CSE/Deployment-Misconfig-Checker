"use client"

import { useState, useEffect } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Code, Loader2 } from "lucide-react"
import { APIClient } from "@/lib/api-client"

interface CodeScannerProps {
  domain: string
}

export function CodeScanner({ domain }: CodeScannerProps) {
  const [isLoading, setIsLoading] = useState(false)
  const [codeData, setCodeData] = useState<{ issues: number; critical: number; quality: string }>({
    issues: 0,
    critical: 0,
    quality: "N/A",
  })

  useEffect(() => {
    if (domain) {
      const fetchCodeData = async () => {
        setIsLoading(true)
        try {
          const apiUrl = process.env.NEXT_PUBLIC_CODE_SCANNER_API || "http://localhost:5004"
          const client = new APIClient(apiUrl)
          const response = await client.submitScan({ domain })

          if (response.success && response.data) {
            setCodeData({
              issues: (response.data as any).total_issues || 0,
              critical: (response.data as any).critical_count || 0,
              quality: (response.data as any).quality_score || "N/A",
            })
          }
        } catch (error) {
          console.error("Error fetching code data:", error)
        } finally {
          setIsLoading(false)
        }
      }

      fetchCodeData()
    }
  }, [domain])

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold text-foreground mb-2">Code Scanner</h1>
        <p className="text-muted-foreground">Analyze source code for vulnerabilities</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium">Issues Found</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center gap-2">
              <div className="text-3xl font-bold">{codeData.issues}</div>
              {isLoading && <Loader2 size={16} className="animate-spin text-muted-foreground" />}
            </div>
            <p className="text-xs text-muted-foreground mt-1">Code vulnerabilities</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium">Critical</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center gap-2">
              <div className="text-3xl font-bold text-accent">{codeData.critical}</div>
              {isLoading && <Loader2 size={16} className="animate-spin text-muted-foreground" />}
            </div>
            <p className="text-xs text-muted-foreground mt-1">Severity issues</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium">Code Quality</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center gap-2">
              <div className="text-3xl font-bold text-green-500">{codeData.quality}</div>
              {isLoading && <Loader2 size={16} className="animate-spin text-muted-foreground" />}
            </div>
            <p className="text-xs text-muted-foreground mt-1">Score</p>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Code size={20} className="text-accent" />
            Code Analysis Results
          </CardTitle>
          <CardDescription>SAST and dependency scanning results</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="text-center py-12 text-muted-foreground">
            {domain ? <p>Scanning {domain} for code vulnerabilities...</p> : <p>Run a scan to analyze source code</p>}
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
