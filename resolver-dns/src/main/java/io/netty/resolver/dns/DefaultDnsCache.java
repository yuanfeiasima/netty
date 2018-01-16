/*
 * Copyright 2016 The Netty Project
 *
 * The Netty Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.netty.resolver.dns;

import io.netty.channel.EventLoop;
import io.netty.handler.codec.dns.DnsRecord;
import io.netty.util.concurrent.ScheduledFuture;
import io.netty.util.internal.PlatformDependent;
import io.netty.util.internal.UnstableApi;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import static io.netty.util.internal.ObjectUtil.checkNotNull;
import static io.netty.util.internal.ObjectUtil.checkPositiveOrZero;

/**
 * Default implementation of {@link DnsCache}, backed by a {@link ConcurrentMap}.
 * If any additional {@link DnsRecord} is used, no caching takes place.
 */
@UnstableApi
public class DefaultDnsCache implements DnsCache {

    private final ConcurrentMap<String, Entries> resolveCache = PlatformDependent.newConcurrentHashMap();

    private final int minTtl;
    private final int maxTtl;
    private final int negativeTtl;

    /**
     * Create a cache that respects the TTL returned by the DNS server
     * and doesn't cache negative responses.
     */
    public DefaultDnsCache() {
        this(0, Integer.MAX_VALUE, 0);
    }

    /**
     * Create a cache.
     * @param minTtl the minimum TTL
     * @param maxTtl the maximum TTL
     * @param negativeTtl the TTL for failed queries
     */
    public DefaultDnsCache(int minTtl, int maxTtl, int negativeTtl) {
        this.minTtl = checkPositiveOrZero(minTtl, "minTtl");
        this.maxTtl = checkPositiveOrZero(maxTtl, "maxTtl");
        if (minTtl > maxTtl) {
            throw new IllegalArgumentException(
                    "minTtl: " + minTtl + ", maxTtl: " + maxTtl + " (expected: 0 <= minTtl <= maxTtl)");
        }
        this.negativeTtl = checkPositiveOrZero(negativeTtl, "negativeTtl");
    }

    /**
     * Returns the minimum TTL of the cached DNS resource records (in seconds).
     *
     * @see #maxTtl()
     */
    public int minTtl() {
        return minTtl;
    }

    /**
     * Returns the maximum TTL of the cached DNS resource records (in seconds).
     *
     * @see #minTtl()
     */
    public int maxTtl() {
        return maxTtl;
    }

    /**
     * Returns the TTL of the cache for the failed DNS queries (in seconds). The default value is {@code 0}, which
     * disables the cache for negative results.
     */
    public int negativeTtl() {
        return negativeTtl;
    }

    @Override
    public void clear() {
        for (Iterator<Map.Entry<String, Entries>> i = resolveCache.entrySet().iterator();
             i.hasNext();) {
            final Map.Entry<String, Entries> e = i.next();
            i.remove();

            List<DefaultDnsCacheEntry> entryList = e.getValue().get();
            if (entryList != null) {
                cancelExpiration(entryList);
            }
        }
    }

    @Override
    public boolean clear(String hostname) {
        checkNotNull(hostname, "hostname");
        Entries entries = resolveCache.remove(hostname);
        if (entries != null) {
            List<DefaultDnsCacheEntry> entryList = entries.get();
            if (entryList != null) {
                cancelExpiration(entryList);
                return true;
            }
        }
        return false;
    }

    private static boolean emptyAdditionals(DnsRecord[] additionals) {
        return additionals == null || additionals.length == 0;
    }

    @Override
    public List<? extends DnsCacheEntry> get(String hostname, DnsRecord[] additionals) {
        checkNotNull(hostname, "hostname");
        if (!emptyAdditionals(additionals)) {
            return null;
        }

        Entries entries = resolveCache.get(hostname);
        return entries == null ? null : entries.get();
    }

    @Override
    public DnsCacheEntry cache(String hostname, DnsRecord[] additionals,
                               InetAddress address, long originalTtl, EventLoop loop) {
        checkNotNull(hostname, "hostname");
        checkNotNull(address, "address");
        checkNotNull(loop, "loop");
        final DefaultDnsCacheEntry e = new DefaultDnsCacheEntry(hostname, address);
        if (maxTtl == 0 || !emptyAdditionals(additionals)) {
            return e;
        }
        final int ttl = Math.max(minTtl, (int) Math.min(maxTtl, originalTtl));

        Entries entries = resolveCache.get(hostname);
        if (entries == null) {
            entries = resolveCache.putIfAbsent(hostname, new Entries(e));
            if (entries == null) {
                scheduleCacheExpiration(entries, e, negativeTtl, loop);
                return e;
            }
        }

        entries.add(e);
        scheduleCacheExpiration(entries, e, ttl, loop);
        return e;
    }

    @Override
    public DnsCacheEntry cache(String hostname, DnsRecord[] additionals, Throwable cause, EventLoop loop) {
        checkNotNull(hostname, "hostname");
        checkNotNull(cause, "cause");
        checkNotNull(loop, "loop");

        final DefaultDnsCacheEntry e = new DefaultDnsCacheEntry(hostname, cause);
        if (negativeTtl == 0 || !emptyAdditionals(additionals)) {
            return e;
        }

        Entries entries = resolveCache.get(hostname);
        if (entries == null) {
            entries = resolveCache.putIfAbsent(hostname, new Entries(e));
            if (entries == null) {
                scheduleCacheExpiration(entries, e, negativeTtl, loop);
                return e;
            }
        }
        entries.add(e);

        scheduleCacheExpiration(entries, e, negativeTtl, loop);
        return e;
    }

    private static void cancelExpiration(List<DefaultDnsCacheEntry> entries) {
        final int numEntries = entries.size();
        for (int i = 0; i < numEntries; i++) {
            entries.get(i).cancelExpiration();
        }
    }

    private void scheduleCacheExpiration(final Entries entries,
                                         final DefaultDnsCacheEntry e,
                                         int ttl,
                                         EventLoop loop) {
        e.scheduleExpiration(loop, new Runnable() {
                    @Override
                    public void run() {
                        if (entries.remove(e)) {
                            resolveCache.remove(e.hostname);
                        }
                    }
                }, ttl, TimeUnit.SECONDS);
    }

    @Override
    public String toString() {
        return new StringBuilder()
                .append("DefaultDnsCache(minTtl=")
                .append(minTtl).append(", maxTtl=")
                .append(maxTtl).append(", negativeTtl=")
                .append(negativeTtl).append(", cached resolved hostname=")
                .append(resolveCache.size()).append(")")
                .toString();
    }

    private static final class DefaultDnsCacheEntry implements DnsCacheEntry {
        private final String hostname;
        private final InetAddress address;
        private final Throwable cause;
        private volatile ScheduledFuture<?> expirationFuture;

        DefaultDnsCacheEntry(String hostname, InetAddress address) {
            this.hostname = checkNotNull(hostname, "hostname");
            this.address = checkNotNull(address, "address");
            cause = null;
        }

        DefaultDnsCacheEntry(String hostname, Throwable cause) {
            this.hostname = checkNotNull(hostname, "hostname");
            this.cause = checkNotNull(cause, "cause");
            address = null;
        }

        @Override
        public InetAddress address() {
            return address;
        }

        @Override
        public Throwable cause() {
            return cause;
        }

        String hostname() {
            return hostname;
        }

        void scheduleExpiration(EventLoop loop, Runnable task, long delay, TimeUnit unit) {
            assert expirationFuture == null : "expiration task scheduled already";
            expirationFuture = loop.schedule(task, delay, unit);
        }

        void cancelExpiration() {
            ScheduledFuture<?> expirationFuture = this.expirationFuture;
            if (expirationFuture != null) {
                expirationFuture.cancel(false);
            }
        }

        @Override
        public String toString() {
            if (cause != null) {
                return hostname + '/' + cause;
            } else {
                return address.toString();
            }
        }
    }

    private static final class Entries {
        private final ReadWriteLock lock = new ReentrantReadWriteLock();
        private final Lock readLock = lock.readLock();
        private final Lock writeLock = lock.writeLock();

        // Access to this field is guarded by the ReadWriteLock.
        //
        // It's important that this List will never be modified itself but just replaced when an new entry is added,
        // or removed.
        private List<DefaultDnsCacheEntry> entries;

        Entries(DefaultDnsCacheEntry entry) {
            entries = Collections.unmodifiableList(Collections.singletonList(entry));
        }

        List<DefaultDnsCacheEntry> get() {
            readLock.lock();
            try {
                return entries;
            } finally {
                readLock.unlock();
            }
        }

        void add(DefaultDnsCacheEntry e) {
            if (e.cause() == null) {
                writeLock.lock();
                try {
                    if (!entries.isEmpty()) {
                        final DefaultDnsCacheEntry firstEntry = entries.get(0);
                        if (firstEntry.cause() != null) {
                            assert entries.size() == 1;
                            firstEntry.cancelExpiration();
                            entries = Collections.unmodifiableList(Collections.singletonList(e));
                            return;
                        }
                    }

                    List<DefaultDnsCacheEntry> newEntries = new ArrayList<DefaultDnsCacheEntry>(entries.size() + 1);
                    newEntries.addAll(entries);
                    newEntries.add(e);
                    entries = Collections.unmodifiableList(newEntries);
                } finally {
                    writeLock.unlock();
                }
            } else {
                List<DefaultDnsCacheEntry> oldEntries;

                writeLock.lock();
                try {
                    oldEntries = entries;
                    entries = Collections.unmodifiableList(Collections.singletonList(e));
                } finally {
                    writeLock.unlock();
                }
                final int numEntries = oldEntries.size();

                for (int i = 0; i < numEntries; i ++) {
                    oldEntries.get(i).cancelExpiration();
                }
            }
        }

        boolean remove(DefaultDnsCacheEntry entry) {
            writeLock.lock();
            try {
                List<DefaultDnsCacheEntry> newEntries = new ArrayList<DefaultDnsCacheEntry>(entries.size());
                for (int i = 0; i < entries.size(); i++) {
                    DefaultDnsCacheEntry e = entries.get(i);
                    if (!e.equals(entry)) {
                        newEntries.add(e);
                    }
                }
                if (newEntries.isEmpty()) {
                    entries = null;
                    return true;
                } else {
                    entries = Collections.unmodifiableList(newEntries);
                    return false;
                }
            } finally {
                writeLock.unlock();
            }
        }
    }
}
