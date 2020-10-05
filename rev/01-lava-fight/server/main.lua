package.path = package.path .. ";./?.lua"

local sock = require("sock/sock")
local json = require("json")
local bitser = require("bitser/bitser")

local gamestate = {
    players = {},
    shots = {}
}

-- get 5 hits in one server tick
-- get hit 3 times and don't die
-- move FAST
local cheaters = {

}

flag1 = "flag{why_1s_"
flag2 = "1t_th4t_3v3ry_g4me"
flag3 = "_ha5_l4v4_1n_it?}"

function printPlayer(p)
    for k, v in pairs(p) do
        print(k, v)
    end
end


function distance(x1, y1, x2, y2)
    return math.sqrt((x2 - x1)^2 + (y2-y1)^2)
end

function impossibleDistance(d)
    -- a little leeway, make it actually really fast
    print("GOT DISTANCE OF ", d)
    print("IMPOSSIBLE DISTANCE IS ", 1284 * .033)
    if d > 1284 * .033 then
        print("Was impossible!")
        return true
    else
        return false
    end
end


function love.conf()
    t.window = false
end

function love.load()
    tickRate = .033
    offset = .014
    stop = false
    tick = 0
    playerTimeout = 8

    server = sock.newServer("*", 9998)
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

    function sanitize(data)
        print("updating gamestate")
        gamestate_update = {
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
        print("gamstate updated")

        for k, v in ipairs(gamestate_update) do
            print(k, " = ", v)
        end

        if gamestate_update["x"] < 0 or gamestate_update["x"] > 7680 then
            print("x", gamestate_update["x"])
        end
        if gamestate_update["y"] < 0 or gamestate_update["y"] > 1920 then
            print("y", gamestate_update["y"])
        end
        if gamestate_update["w"] > 256 or gamestate_update["w"] < 0 then
            print("w", gamestate_update["w"])
        end
        if gamestate_update["h"] > 64 or gamestate_update["h"] < 0 then
            print("h", gamestate_update["h"])
        end
        if gamestate_update["animation"] ~= "walk" and gamestate_update["animation"] ~= "still" and gamestate_update["animation"] ~= "jump" and gamestate_update["animation"] ~= "fire" and gamestate_update["animation"] ~= "death" then
            print("animation", gamestate_update["animation"])
        end
        if gamestate_update["direction"] ~= "left" and gamestate_update["direction"] ~= "right" then
            print("direction", gamestate_update["direction"])
        end
        print("Sanitize success")
        return false
    end

    server:on("update", function(data, peer)
        local status, err = pcall(sanitize, data)
        if status then
            if tableHasKey(gamestate.players, data.name) then
                printPlayer(gamestate.players[data.name])
                printPlayer(data)
                local id = impossibleDistance(distance(data.x, data.y, gamestate.players[data.name].x, gamestate.players[data.name].y))
                if id then
                    if gamestate.players[data.name].hp ~= 0 then
                        if not tableHasKey(cheaters, data.name) then
                            cheaters[data.name] = {
                                ["speed"] = 1,
                            }
                        else
                            cheaters[data.name]["speed"] = 1
                        end
                    end
                end
                if gamestate.players[data.name].hp < data.hp and gamestate.players[data.name].hp ~= 0 then
                    if not tableHasKey(cheaters, data.name) then
                        cheaters[data.name] = {
                            ["deathless"] = 1,
                        }
                    else
                        cheaters[data.name].deathless = 1
                    end
                    
                end
            end
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
            if tableHasKey(cheaters, data.name) then
                local cheater = cheaters[data.name]
                if tableHasKey(cheater, "speed") and cheater["speed"] == 1 then
                    print("(************************************)")
                    print("SETTING SPEED FLAG")
                    peer:send("flag", "speed: " .. flag1)
                    cheater["speed"] = nil
                end
                if tableHasKey(cheater, "deathless") and cheater["deathless"] == 1 then
                    peer:send("flag", "deathless: " .. flag2)
                    cheater["deathless"] = nil
                end
                if tableHasKey(cheater, "spree") and cheater["spree"] == 1 then
                    peer:send("flag", "spree: " .. flag3)
                    cheater["spree"] = nil
                end
            end
        else
            print("Sanitizer error: ", err)
            peer:send("error", "stop that!")
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

function tableHasKey(table,key)
    return table[key] ~= nil
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
                        print("Player ", n, " took damage")
                        if not tableHasKey(cheaters, shotc.shooter) then
                            cheaters[shotc.shooter] = {
                                ["hits"] = 1,
                            }
                        else
                            cheaters[shotc.shooter].hits = cheaters[shotc.shooter].hits + 1
                            if cheaters[shotc.shooter].hits >= 5 then
                                cheaters[shotc.shooter]["spree"] = 1
                            end
                        end
                        
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
            if tableHasKey(cheaters, id) then
                cheaters[id].hits = 0
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
