"use client"

import { useState, useEffect } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Zap, Loader2 } from "lucide-react"
import { APIClient } from "@/lib/api-client"

interface APIDiscoveryProps {
  domain: string
}

export function APIDiscovery({ domain }: APIDiscoveryProps) {
  const [isLoading, setIsLoading] = useState(false)
  const [apiData, setApiData] = useState<{ found: number; unauthenticated: number; sensitiveData: number }>({
    found: 0,
    unauthenticated: 0,
    sensitiveData: 0,
  })

  useEffect(() => {
    if (domain) {
      const fetchAPIData = async () => {
        setIsLoading(true)
        try {
          const apiUrl = process.env.NEXT_PUBLIC_API_DISCOVERY_API || "http://localhost:5003"
          const client = new APIClient(apiUrl)
          const response = await client.submitScan({ domain })

          if (response.success && response.data) {
            setApiData({
              found: (response.data as any).apis_found || 0,
              unauthenticated: (response.data as any).unauthenticated_count || 0,
              sensitiveData: (response.data as any).sensitive_data_count || 0,
            })
          }
        } catch (error) {
          console.error("Error fetching API data:", error)
        } finally {
          setIsLoading(false)
        }
      }

      fetchAPIData()
    }
  }, [domain])

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold text-foreground mb-2">API Discovery (Kethaka)</h1>
        <p className="text-muted-foreground">Discover and analyze API endpoints</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium">APIs Found</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center gap-2">
              <div className="text-3xl font-bold">{apiData.found}</div>
              {isLoading && <Loader2 size={16} className="animate-spin text-muted-foreground" />}
            </div>
            <p className="text-xs text-muted-foreground mt-1">Endpoints discovered</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium">Unauthenticated</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center gap-2">
              <div className="text-3xl font-bold text-accent">{apiData.unauthenticated}</div>
              {isLoading && <Loader2 size={16} className="animate-spin text-muted-foreground" />}
            </div>
            <p className="text-xs text-muted-foreground mt-1">Endpoints</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium">Sensitive Data</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center gap-2">
              <div className="text-3xl font-bold text-orange-500">{apiData.sensitiveData}</div>
              {isLoading && <Loader2 size={16} className="animate-spin text-muted-foreground" />}
            </div>
            <p className="text-xs text-muted-foreground mt-1">Exposures found</p>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Zap size={20} className="text-accent" />
            API Endpoints
          </CardTitle>
          <CardDescription>REST, GraphQL, and other API endpoints</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="text-center py-12 text-muted-foreground">
            {domain ? <p>Scanning {domain} for API endpoints...</p> : <p>Run a scan to discover API endpoints</p>}
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
