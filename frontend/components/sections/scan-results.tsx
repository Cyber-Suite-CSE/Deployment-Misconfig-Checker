"use client"

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Button } from "@/components/ui/button"
import { ArrowLeft, Globe, Server, Code, Shield, Network, Lock } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { ScrollArea } from "@/components/ui/scroll-area"

interface ScanResultsProps {
  data: any
  onBack: () => void
}

export function ScanResults({ data, onBack }: ScanResultsProps) {
  const domainEnum = data.modules?.domain_enumeration
  const serviceDiscovery = data.modules?.service_discovery
  const webAnalysis = data.modules?.web_analysis
  const fingerprinting = domainEnum?.modules?.fingerprinting
  const dnsModule = domainEnum?.modules?.dns
  const passiveModule = domainEnum?.modules?.passive

  const totalSubdomains = domainEnum?.all_subdomains?.length || 0
  const openPorts = Object.keys(serviceDiscovery?.service_results?.services || {}).length
  const technologies = fingerprinting?.summary?.unique_technologies || []
  const apis = webAnalysis?.web_crawl?.apis || []
  const securityIssues = fingerprinting?.summary?.common_issues || []

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-4">
        <Button onClick={onBack} variant="outline" size="sm" className="gap-2 bg-transparent">
          <ArrowLeft size={16} />
          Back to Scan
        </Button>
        <div>
          <h2 className="text-2xl font-bold text-foreground">Scan Results</h2>
          <p className="text-sm text-muted-foreground">Target: {data.target_domain}</p>
          <p className="text-xs text-muted-foreground mt-1">Execution Time: {data.execution_time?.toFixed(2)}s</p>
        </div>
      </div>

      {/* Summary Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Total Subdomains</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-accent">{totalSubdomains}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Open Ports</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-accent">{openPorts}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Technologies</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-accent">{technologies.length}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">APIs Found</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-accent">{apis.length}</div>
          </CardContent>
        </Card>
      </div>

      {/* Detailed Results */}
      <Tabs defaultValue="domain" className="w-full">
        <TabsList className="grid w-full grid-cols-5">
          <TabsTrigger value="domain" className="gap-2">
            <Globe size={16} />
            <span className="hidden sm:inline">Domain</span>
          </TabsTrigger>
          <TabsTrigger value="dns" className="gap-2">
            <Network size={16} />
            <span className="hidden sm:inline">DNS</span>
          </TabsTrigger>
          <TabsTrigger value="services" className="gap-2">
            <Server size={16} />
            <span className="hidden sm:inline">Services</span>
          </TabsTrigger>
          <TabsTrigger value="tech" className="gap-2">
            <Code size={16} />
            <span className="hidden sm:inline">Tech</span>
          </TabsTrigger>
          <TabsTrigger value="security" className="gap-2">
            <Shield size={16} />
            <span className="hidden sm:inline">Security</span>
          </TabsTrigger>
        </TabsList>

        {/* Domain Enumeration */}
        <TabsContent value="domain" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Subdomains Found</CardTitle>
              <CardDescription>{totalSubdomains} unique subdomains discovered</CardDescription>
            </CardHeader>
            <CardContent>
              <ScrollArea className="h-96 w-full rounded-md border border-border p-4">
                <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-2">
                  {domainEnum?.all_subdomains?.map((subdomain: string) => (
                    <Badge key={subdomain} variant="secondary" className="text-xs justify-center">
                      {subdomain}
                    </Badge>
                  ))}
                </div>
              </ScrollArea>
            </CardContent>
          </Card>

          {/* Passive Reconnaissance */}
          {passiveModule && (
            <Card>
              <CardHeader>
                <CardTitle>Passive Reconnaissance</CardTitle>
                <CardDescription>Certificate Transparency & Public Records</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div>
                  <h4 className="font-semibold text-sm mb-2">Certificates Analyzed</h4>
                  <p className="text-sm text-muted-foreground">
                    {passiveModule.statistics?.certificates_analyzed || 0} certificates
                  </p>
                </div>
                <div>
                  <h4 className="font-semibold text-sm mb-2">CT Logs Processed</h4>
                  <p className="text-sm text-muted-foreground">
                    {passiveModule.statistics?.ct_logs_processed || 0} logs
                  </p>
                </div>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        {/* DNS Records */}
        <TabsContent value="dns" className="space-y-4">
          {dnsModule?.dns_records && (
            <Card>
              <CardHeader>
                <CardTitle>DNS Records</CardTitle>
                <CardDescription>{dnsModule.statistics?.total_records || 0} total records found</CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                {Object.entries(dnsModule.dns_records).map(([type, records]: [string, any]) => (
                  <div key={type}>
                    <h4 className="font-semibold text-sm mb-3 flex items-center gap-2">
                      <Badge variant="outline">{type}</Badge>
                      <span className="text-xs text-muted-foreground">
                        {Array.isArray(records) ? records.length : 1} record(s)
                      </span>
                    </h4>
                    <ScrollArea className="h-40 w-full rounded-md border border-border p-3">
                      <div className="space-y-1">
                        {Array.isArray(records) ? (
                          records.map((record: string, idx: number) => (
                            <p key={idx} className="text-sm text-muted-foreground font-mono break-all">
                              {record}
                            </p>
                          ))
                        ) : (
                          <p className="text-sm text-muted-foreground font-mono">{records}</p>
                        )}
                      </div>
                    </ScrollArea>
                  </div>
                ))}
              </CardContent>
            </Card>
          )}

          {/* DNS Analysis */}
          {dnsModule?.analysis && (
            <Card>
              <CardHeader>
                <CardTitle>DNS Analysis</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                {dnsModule.analysis.txt_analysis?.spf && (
                  <div>
                    <h4 className="font-semibold text-sm mb-2">SPF Records</h4>
                    <div className="space-y-1">
                      {dnsModule.analysis.txt_analysis.spf.map((record: string, idx: number) => (
                        <p key={idx} className="text-sm text-muted-foreground font-mono break-all">
                          {record}
                        </p>
                      ))}
                    </div>
                  </div>
                )}
                {dnsModule.analysis.txt_analysis?.dmarc && dnsModule.analysis.txt_analysis.dmarc.length > 0 && (
                  <div>
                    <h4 className="font-semibold text-sm mb-2">DMARC Records</h4>
                    <div className="space-y-1">
                      {dnsModule.analysis.txt_analysis.dmarc.map((record: string, idx: number) => (
                        <p key={idx} className="text-sm text-muted-foreground font-mono break-all">
                          {record}
                        </p>
                      ))}
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          )}
        </TabsContent>

        {/* Services */}
        <TabsContent value="services" className="space-y-4">
          {serviceDiscovery?.service_results?.services && (
            <Card>
              <CardHeader>
                <CardTitle>Open Services</CardTitle>
                <CardDescription>{openPorts} services identified</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {Object.entries(serviceDiscovery.service_results.services).map(([port, service]: [string, any]) => (
                    <div key={port} className="flex items-center justify-between p-3 rounded-lg border border-border">
                      <div>
                        <p className="font-semibold">{service.service}</p>
                        <p className="text-sm text-muted-foreground">Port {service.port}</p>
                      </div>
                      <div className="flex items-center gap-2">
                        <Badge variant={service.ssl ? "default" : "secondary"}>
                          {service.ssl ? "SSL/TLS" : "Plain"}
                        </Badge>
                        {service.version && <span className="text-sm text-muted-foreground">{service.version}</span>}
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}

          {/* Service Summary */}
          {serviceDiscovery?.summary && (
            <Card>
              <CardHeader>
                <CardTitle>Service Summary</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                <div className="flex justify-between">
                  <span className="text-sm">Total Services</span>
                  <span className="font-semibold">{serviceDiscovery.summary.total_services}</span>
                </div>
                {serviceDiscovery.summary.ssl_services?.length > 0 && (
                  <div className="flex justify-between">
                    <span className="text-sm">SSL/TLS Services</span>
                    <span className="font-semibold">{serviceDiscovery.summary.ssl_services.length}</span>
                  </div>
                )}
              </CardContent>
            </Card>
          )}
        </TabsContent>

        {/* Technology Stack */}
        <TabsContent value="tech" className="space-y-4">
          {technologies.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle>Detected Technologies</CardTitle>
                <CardDescription>{technologies.length} technologies identified</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="flex flex-wrap gap-2">
                  {technologies.map((tech: string) => (
                    <Badge key={tech} variant="outline" className="text-xs">
                      {tech}
                    </Badge>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}

          {apis.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle>Discovered APIs</CardTitle>
                <CardDescription>{apis.length} API endpoints found</CardDescription>
              </CardHeader>
              <CardContent>
                <ScrollArea className="h-96 w-full rounded-md border border-border p-3">
                  <div className="space-y-2">
                    {apis.map((api: string, idx: number) => (
                      <div key={idx} className="p-2 rounded bg-muted text-xs font-mono text-muted-foreground break-all">
                        {api}
                      </div>
                    ))}
                  </div>
                </ScrollArea>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        {/* Security Issues */}
        <TabsContent value="security" className="space-y-4">
          {securityIssues.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle>Security Issues Found</CardTitle>
                <CardDescription>{securityIssues.length} issues detected</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  {securityIssues.map((issue: string) => (
                    <div
                      key={issue}
                      className="flex items-center gap-2 p-2 rounded bg-muted/50 border border-accent/20"
                    >
                      <Lock size={16} className="text-accent flex-shrink-0" />
                      <span className="text-sm">{issue}</span>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}

          {/* CDN Detection */}
          {webAnalysis?.cdn_detection && (
            <Card>
              <CardHeader>
                <CardTitle>CDN Detection</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="flex items-center justify-between">
                  <span className="text-sm">CDN Detected</span>
                  <Badge variant={webAnalysis.cdn_detection.cdn_detected ? "default" : "secondary"}>
                    {webAnalysis.cdn_detection.cdn_name || "None"}
                  </Badge>
                </div>
              </CardContent>
            </Card>
          )}

          {/* Fingerprinting Summary */}
          {fingerprinting?.summary && (
            <Card>
              <CardHeader>
                <CardTitle>Security Score</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="flex items-center justify-between">
                  <span className="text-sm">Average Security Score</span>
                  <span className="text-2xl font-bold text-accent">
                    {fingerprinting.summary.security_score_avg?.toFixed(1) || "N/A"}%
                  </span>
                </div>
              </CardContent>
            </Card>
          )}
        </TabsContent>
      </Tabs>
    </div>
  )
}
