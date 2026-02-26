'use client';

import { useQuery } from '@tanstack/react-query';
import { api } from '@/lib/api';
import ContractCard from '@/components/ContractCard';
import ContractCardSkeleton from '@/components/ContractCardSkeleton';
import LoadingSkeleton from '@/components/LoadingSkeleton';
import { Search, Package, CheckCircle, Users, ArrowRight, Sparkles } from 'lucide-react';
import Link from 'next/link';
import { useEffect, useRef, useState } from 'react';
import { useAnalytics } from '@/hooks/useAnalytics';
import Navbar from '@/components/Navbar';

export default function Home() {
  const [searchQuery, setSearchQuery] = useState('');
  const searchInputRef = useRef<HTMLInputElement>(null);
  const { logEvent } = useAnalytics();

  const { data: stats, isLoading: statsLoading } = useQuery({
    queryKey: ['stats'],
    queryFn: () => api.getStats(),
  });

  const { data: recentContracts, isLoading: contractsLoading } = useQuery({
    queryKey: ['contracts', 'recent'],
    queryFn: () => api.getContracts({ page: 1, page_size: 6 }),
  });

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    if (searchQuery.trim()) {
      logEvent('search_performed', {
        keyword: searchQuery.trim(),
        source: 'home_hero',
      });
      window.location.href = `/contracts?query=${encodeURIComponent(searchQuery)}`;
    }
  };

  useEffect(() => {
    const handleKeyDown = (event: KeyboardEvent) => {
      const isSlashShortcut = event.key === '/' || event.code === 'Slash';
      if (!isSlashShortcut || event.ctrlKey || event.metaKey || event.altKey) return;

      const activeElement = document.activeElement as HTMLElement | null;
      const isTypingField = Boolean(
        activeElement &&
        (activeElement.tagName === 'INPUT' ||
          activeElement.tagName === 'TEXTAREA' ||
          activeElement.tagName === 'SELECT' ||
          activeElement.isContentEditable),
      );

      if (isTypingField) return;

      event.preventDefault();
      searchInputRef.current?.focus();
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  return (
    <div className="min-h-screen bg-background text-foreground">
      <Navbar />

      {/* Hero Section */}
      <section className="relative overflow-hidden">
        <div className="absolute inset-0 bg-grid-pattern opacity-5 text-primary" />
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-24 relative">
          <div className="text-center max-w-3xl mx-auto">
            <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-primary/10 text-primary text-sm font-medium mb-6">
              <Sparkles className="w-4 h-4" />
              The Official Soroban Smart Contract Registry
            </div>

            <h1 className="text-5xl sm:text-6xl font-bold mb-6 leading-tight">
              Discover & Publish
              <br />
              <span className="bg-linear-to-r from-blue-600 via-purple-600 to-pink-600 dark:from-blue-400 dark:via-purple-400 dark:to-pink-400 bg-clip-text text-transparent">
                Soroban Contracts
              </span>
            </h1>

            <p className="text-xl text-muted-foreground mb-12">
              The trusted registry for verified smart contracts on the Stellar network.
              Find, deploy, and share Soroban contracts with the community.
            </p>

            {/* Search Bar */}
            <form onSubmit={handleSearch} className="max-w-2xl mx-auto mb-12">
              <div className="relative">
                <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-muted-foreground" />
                <input
                  ref={searchInputRef}
                  type="text"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder="Search contracts by name, category, or tag..."
                  aria-label="Search contracts"
                  aria-keyshortcuts="/"
                  className="w-full pl-12 pr-4 py-4 rounded-xl border border-border bg-background text-foreground placeholder-muted-foreground focus:outline-none focus:ring-2 focus:ring-primary shadow-lg"
                />
                <button
                  type="submit"
                  className="absolute right-2 top-1/2 -translate-y-1/2 px-6 py-2 rounded-lg bg-primary text-primary-foreground hover:opacity-90 transition-opacity font-medium"
                >
                  Search
                </button>
              </div>
            </form>

            {/* Stats */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-6 max-w-3xl mx-auto">
              {statsLoading ? (
                <>
                  {[1, 2, 3].map((i) => (
                    <div key={i} className="bg-background rounded-xl p-6 border border-border shadow-sm">
                      <div className="flex items-center justify-center gap-2 mb-2">
                        <LoadingSkeleton width="3rem" height="2.25rem" />
                      </div>
                      <LoadingSkeleton width="7rem" height="0.875rem" className="mx-auto" />
                    </div>
                  ))}
                </>
              ) : stats ? (
                <>
                  <div className="bg-background rounded-xl p-6 border border-border shadow-sm">
                    <div className="flex items-center justify-center gap-2 mb-2">
                      <Package className="w-5 h-5 text-primary" />
                      <span className="text-3xl font-bold">
                        {stats.total_contracts}
                      </span>
                    </div>
                    <p className="text-sm text-muted-foreground">Total Contracts</p>
                  </div>

                  <div className="bg-background rounded-xl p-6 border border-border shadow-sm">
                    <div className="flex items-center justify-center gap-2 mb-2">
                      <CheckCircle className="w-5 h-5 text-green-500" />
                      <span className="text-3xl font-bold">
                        {stats.verified_contracts}
                      </span>
                    </div>
                    <p className="text-sm text-muted-foreground">Verified</p>
                  </div>

                  <div className="bg-background rounded-xl p-6 border border-border shadow-sm">
                    <div className="flex items-center justify-center gap-2 mb-2">
                      <Users className="w-5 h-5 text-secondary" />
                      <span className="text-3xl font-bold">
                        {stats.total_publishers}
                      </span>
                    </div>
                    <p className="text-sm text-muted-foreground">Publishers</p>
                  </div>
                </>
              ) : null}
            </div>
          </div>
        </div>
      </section>

      {/* Recent Contracts */}
      <section className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-16">
        <div className="flex items-center justify-between mb-8">
          <h2 className="text-3xl font-bold">
            Recent Contracts
          </h2>
          <Link
            href="/contracts"
            className="flex items-center gap-2 text-primary hover:opacity-80 font-medium transition-opacity"
          >
            View all
            <ArrowRight className="w-4 h-4" />
          </Link>
        </div>

        {contractsLoading ? (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {[1, 2, 3, 4, 5, 6].map((i) => (
              <ContractCardSkeleton key={i} />
            ))}
          </div>
        ) : recentContracts && (recentContracts.items?.length ?? 0) > 0 ? (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {(recentContracts.items ?? []).map((contract) => (
              <ContractCard key={contract.id} contract={contract} />
            ))}
          </div>
        ) : (
          <div className="text-center py-12 bg-white dark:bg-gray-900 rounded-xl border border-gray-200 dark:border-gray-800">
            <Package className="w-12 h-12 text-gray-400 mx-auto mb-4" />
            <p className="text-gray-600 dark:text-gray-400">No contracts published yet</p>
          </div>
        )}
      </section>

      {/* Footer */}
      <footer className="border-t border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-900 mt-24" aria-label="Site footer">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
          <div className="flex flex-col items-center gap-3 text-gray-600 dark:text-gray-400">
            <div className="flex items-center gap-2">
              <Users className="w-5 h-5 text-blue-600 dark:text-blue-400" aria-hidden="true" />
              <span>Built for the Stellar Dev Community</span>
            </div>
            <p className="text-sm">Powered by Soroban Smart Contracts</p>
          </div>
        </div>
      </footer>
    </div>
  );
}
