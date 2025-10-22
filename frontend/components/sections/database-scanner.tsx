"use client"

import { useState, useEffect } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Database, Loader2 } from "lucide-react"
import { APIClient } from "@/lib/api-client"

interface DatabaseScannerProps {
  domain: string
}

export function DatabaseScanner({ domain }: DatabaseScannerProps) {
  const [isLoading, setIsLoading] = useState(false)
  const [dbData, setDbData] = useState<{ found: number; exposed: number; weakAuth: number }>({
    found: 0,
    exposed: 0,
    weakAuth: 0,
  })

  useEffect(() => {
    if (domain) {
      const fetchDatabaseData = async () => {
        setIsLoading(true)
        try {
          const apiUrl = process.env.NEXT_PUBLIC_DATABASE_SCANNER_API || "http://localhost:5002"
          const client = new APIClient(apiUrl)
          const response = await client.submitScan({ domain })

          if (response.success && response.data) {
            setDbData({
              found: (response.data as any).databases_found || 0,
              exposed: (response.data as any).exposed_records || 0,
              weakAuth: (response.data as any).weak_auth_count || 0,
            })
          }
        } catch (error) {
          console.error("Error fetching database data:", error)
        } finally {
          setIsLoading(false)
        }
      }

      fetchDatabaseData()
    }
  }, [domain])

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold text-foreground mb-2">Database Scanner</h1>
        <p className="text-muted-foreground">Discover and analyze database services</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium">Databases Found</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center gap-2">
              <div className="text-3xl font-bold">{dbData.found}</div>
              {isLoading && <Loader2 size={16} className="animate-spin text-muted-foreground" />}
            </div>
            <p className="text-xs text-muted-foreground mt-1">Active instances</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium">Exposed Data</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center gap-2">
              <div className="text-3xl font-bold text-accent">{dbData.exposed}</div>
              {isLoading && <Loader2 size={16} className="animate-spin text-muted-foreground" />}
            </div>
            <p className="text-xs text-muted-foreground mt-1">Records at risk</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium">Weak Auth</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center gap-2">
              <div className="text-3xl font-bold text-orange-500">{dbData.weakAuth}</div>
              {isLoading && <Loader2 size={16} className="animate-spin text-muted-foreground" />}
            </div>
            <p className="text-xs text-muted-foreground mt-1">Instances detected</p>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Database size={20} className="text-accent" />
            Database Instances
          </CardTitle>
          <CardDescription>Detected database services and configurations</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="text-center py-12 text-muted-foreground">
            {domain ? <p>Scanning {domain} for databases...</p> : <p>Run a scan to discover database services</p>}
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
