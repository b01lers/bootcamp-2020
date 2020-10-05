package.path = package.path .. ";./?.lua"


local sock = require("sock/sock")
local json = require("json")
local bitser = require("bitser/bitser")

local gamestate = {
    players = {},
    shots = {}
}

function love.load()
    tickRate = .033
    offset = .014
    stop = false
    tick = 0
    playerTimeout = 8

    server = sock.newServer("localhost", 9999)
    server:setSerialization(bitser.dumps, bitser.loads)

    server:setSchema("state", {
        "players",
        "shots"
    })

    server:setSchema("update", {
        "name",
        "x",
        "y",
        "w",
        "h",
        "animation",
        "dead",
        "jump",
        "direction",
        "hp",
        "shots"
    })

    server:on("ping", function(data, peer)
        peer:send("pong", "hello")
    end)

    server:on("pong", function(data, peer)
        print("Got pong.")
    end)

    server:on("connect", function(data, peer)
        print("Client has connected.")
    end)

    server:on("disconnect", function(data, peer)
        print("Client has disconnected")

    end)

    server:on("update", function(data, peer)
        gamestate.players[data.name] = {
            ["name"] = data.name,
            ["x"] = data.x,
            ["y"] = data.y,
            ["w"] = data.w,
            ["h"] = data.h,
            ["animation"] = data.animation,
            ["dead"] = data.dead,
            ["jump"] = data.jump,
            ["direction"] = data.direction,
            ["hp"] = data.hp,
            ["time"] = love.timer.getTime()
        }
        if data.shots then
            for _, shot in pairs(data.shots) do
                table.insert(gamestate.shots, {["shooter"] = data.name, ["shot"] = shot})
            end
        end
    end)
end

function sign(n) 
    return n>0 and 1 or n<0 and -1 or 0 
end
function checkIntersect(l1p1, l1p2, l2p1, l2p2)
	local function checkDir(pt1, pt2, pt3) return sign(((pt2.x-pt1.x)*(pt3.y-pt1.y)) - ((pt3.x-pt1.x)*(pt2.y-pt1.y))) end
	return (checkDir(l1p1,l1p2,l2p1) ~= checkDir(l1p1,l1p2,l2p2)) and (checkDir(l2p1,l2p2,l1p1) ~= checkDir(l2p1,l2p2,l1p2))
end

function isHit(x1, y1, x2, y2, xc, yc, w, h)
    s1, s2 = {["x"] = x1,["y"] = y1}, {["x"] = x2,["y"] = y2}
    l1, l2 = {["x"] = xc,["y"] = yc}, {["x"] = xc,["y"] = yc+h}
    r1, r2 = {["x"] = xc+w,["y"] = yc}, {["x"] = xc+w,["y"] = yc+h}
    t1, t2 = {["x"] = xc,["y"] = yc}, {["x"] = xc+w,["y"] = yc}
    b1, b2 = {["x"] = xc,["y"] = yc+h}, {["x"] = xc+w,["y"] = yc+h}
    if checkIntersect(s1, s2, l1, l2) or checkIntersect(s1, s2, r1, r2) or checkIntersect(s1, s2, t1, t2) or checkIntersect(s1, s2, b1, b2) then
        return true
    else
        return false
    end
end

function mainUpdate(dt)
    server:update()

    tick = tick + dt
    if tick > offset and not stop then
        for _, shotc in pairs(gamestate.shots) do
            local x1, y1, x2, y2 = unpack(shotc.shot)
            for n, p in pairs(gamestate.players) do
                if n ~= shotc.shooter then
                    if isHit(x1, y1, x2, y2, p["x"], p["y"], p["w"], p["w"]) then
                        p.hp = p.hp - 1
                    end
                end
            end
        end
        
        stop = true
        server:sendToAll("state", {
            gamestate.players,
            gamestate.shots
        })

        gamestate.shots = {}

        local time = love.timer.getTime()
        for id, player in pairs(gamestate.players) do
            if time - player.time > playerTimeout then
                gamestate.players[id] = nil
            end
        end
    end

    if tick > tickRate then
        tick = 0
        stop = false
        server:sendToAll("request")
    end
end

function testUpdate(dt)
    tick = tick + dt
    if tick > tickRate then
        tick = 0
        server:sendToAll("ping", "hello")
    end
    server:update()
end

function love.update(dt)
    mainUpdate(dt)
end

-- TODO: I should probably add some achievements....here's some ideas:
-- - Kill 5 players in 5 seconds
-- - Fall into lava without dying....or just survive some serious shit
-- - Hmm...TODO: add a deep upgrade and progression system...ideas for that:
-- - Upgrade flight speed....people should go super fast!
-- - One shot, one kill (????)
