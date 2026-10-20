-- One user's IP and device admission is a single Redis transaction.
-- KEYS are explicitly supplied; braces keep this user's keys in one slot.
local nowParts = redis.call('TIME')
local now = tonumber(nowParts[1]) * 1000 + math.floor(tonumber(nowParts[2]) / 1000)
local operation, token = ARGV[1], ARGV[2]
local ttl, grace = tonumber(ARGV[3]), tonumber(ARGV[4])

-- First check both quotas without adding either identity.
for i = 1, 2 do
    local identity, limit = ARGV[3 + i * 2], tonumber(ARGV[4 + i * 2])
    if identity ~= '' and limit > 0 then
        local group = KEYS[i * 2 - 1]
        redis.call('ZREMRANGEBYSCORE', group, '-inf', now)
        if operation == 'acquire' and not redis.call('ZSCORE', group, identity)
            and redis.call('ZCARD', group) >= limit then
            return i
        end
    end
end

for i = 1, 2 do
    local identity, limit = ARGV[3 + i * 2], tonumber(ARGV[4 + i * 2])
    if identity ~= '' and limit > 0 then
        local group, leases = KEYS[i * 2 - 1], KEYS[i * 2]
        redis.call('ZREMRANGEBYSCORE', leases, '-inf', now)
        if operation == 'release' then
            redis.call('ZREM', leases, token)
        else
            -- Renewal also re-registers connections admitted locally during an
            -- outage. Existing connections are not evicted after recovery.
            redis.call('ZADD', leases, now + ttl, token)
        end
        local last = redis.call('ZRANGE', leases, -1, -1, 'WITHSCORES')
        local untilTime = now + grace
        if #last > 0 then untilTime = tonumber(last[2]) + grace end
        redis.call('ZADD', group, untilTime, identity)
        redis.call('PEXPIRE', leases, math.max(1, untilTime - now))
        local groupLast = redis.call('ZRANGE', group, -1, -1, 'WITHSCORES')
        redis.call('PEXPIRE', group, math.max(1, tonumber(groupLast[2]) - now))
    end
end
return 0
