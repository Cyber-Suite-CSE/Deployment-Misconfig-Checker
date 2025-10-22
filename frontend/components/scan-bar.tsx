"use client"

import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Play, Loader2 } from "lucide-react"

interface ScanBarProps {
  domain: string
  onDomainChange: (domain: string) => void
  onExecute: () => void
  isExecuting: boolean
}

export function ScanBar({ domain, onDomainChange, onExecute, isExecuting }: ScanBarProps) {
  return (
    <div className="h-20 border-b border-border bg-card px-6 flex items-center gap-4">
      <div className="flex-1 flex gap-3">
        <Input
          placeholder="Enter domain or URL (e.g., example.com)"
          value={domain}
          onChange={(e) => onDomainChange(e.target.value)}
          className="flex-1"
        />
      </div>
      <Button
        onClick={onExecute}
        disabled={!domain || isExecuting}
        className="gap-2 bg-accent hover:bg-accent/90 text-accent-foreground"
      >
        {isExecuting ? (
          <>
            <Loader2 size={18} className="animate-spin" />
            Executing...
          </>
        ) : (
          <>
            <Play size={18} />
            Execute
          </>
        )}
      </Button>
    </div>
  )
}
