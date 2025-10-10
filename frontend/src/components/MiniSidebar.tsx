'use client';

import { Shield, Bug, Network } from 'lucide-react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';

export default function MiniSidebar() {
  const pathname = usePathname();

  const services = [
    {
      href: '/misconfig',
      icon: Shield,
      label: 'Misconfiguration Check'
    },
    {
      href: '/cve',
      icon: Bug,
      label: 'CVE Check'
    },
    {
      href: '/agent',
      icon: Network,
      label: 'Agentic Workflow'
    }
  ];

  return (
    <div className="absolute left-0 top-0 h-screen w-[70px] bg-muted flex flex-col items-center py-6 z-50 border-r">
      <div className="flex flex-col gap-4">
        {services.map((service) => {
          const Icon = service.icon;
          const isActive = pathname === service.href;
          
          return (
            <Link
              key={service.href}
              href={service.href}
              className={`
                w-12 h-12 rounded-lg flex items-center justify-center
                transition-all duration-200 ease-in-out
                group relative
                ${isActive 
                  ? 'bg-primary text-primary-foreground' 
                  : 'bg-transparent text-muted-foreground hover:text-foreground hover:bg-accent'
                }
              `}
              title={service.label}
            >
              <Icon size={24} strokeWidth={2} />
              
              <div className="absolute left-full ml-2 px-3 py-2 bg-popover text-popover-foreground text-sm rounded-md
                opacity-0 invisible group-hover:opacity-100 group-hover:visible
                transition-all duration-200 whitespace-nowrap pointer-events-none">
                {service.label}
              </div>
            </Link>
          );
        })}
      </div>
    </div>
  );
}
