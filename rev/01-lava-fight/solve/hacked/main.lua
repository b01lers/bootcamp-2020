function getYellowPlayerAnimations()
    walk = newAnimation("walk", newImage("sprites/player-yellow/walk.png"), 32, 48, .9)
    still = newAnimation("still", newImage("sprites/player-yellow/still.png"), 32, 48, .3)
    jump = newAnimation("jump", newImage("sprites/player-yellow/jump.png"), 32, 48, .3)
    fire = newAnimation("fire", newImage("sprites/player-yellow/fire_body.png"), 32, 48, .3)
    death = newAnimation("death", newImage("sprites/concussive_explosion_256x256px.png"), 256, 256, 1.2)
    return walk, still, jump, fire, death
end


function newYellowPlayer(name)
    local x, y = map:getRandomSpawnPoint()
    --print("random spawn at ", x, y)
    walk, still, jump, fire, death = getYellowPlayerAnimations()
    local player = Player(
        name,
        "sprites/player-yellow/still.png", 
        x, 
        y, 
        walk,
        still,
        jump,
        fire,
        death,
        cam,
        {95, 205, 228})
    return player
end

function newNPC(name, x, y)
    walk, still, jump, fire, death = getYellowPlayerAnimations()
    local player = NonPlayerCharacter(
        name, 
        "sprites/player-yellow/still.png",
        x,
        y,
        walk,
        still,
        jump,
        fire,
        death,
        {229, 38, 38})
    return player
end

function connectServer(server, port, username)
    client = sock.newClient(tostring(server), tonumber(port))
    client:setSerialization(bitser.dumps, bitser.loads)

    client:setSchema("state", {
        "players",
        "shots"
    })

    client:setSchema("update", {
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


    client:on("connect", function(data)
        print("Connected to game server, ", server, ":", port)
    end)

    client:on("disconnect", function(data)
        print("Disconnected from game server.")
    end)

    client:on("request", function(data)
        client:send("update", player:getNetworkUpdate(username))
    end)

    client:on("flag", function(data)
        print(data)
    end)

    client:on("error", function(data)
        print(data)
        love.event.quit()
    end)

    client:on("state", function(data)
        gamestate.players = data.players
        gamestate.shots = data.shots
    end)

    client:connect()
end

function titleScreenUpdate(dt)
    introAnimation:update(dt)
end

function titleScreenDraw()
    introAnimation:draw()
end

function titleScreenKeyPressed(key)
    getConfig()
end

function titleScreenInit()
    introAnimation = MultiImageAnimation("sprites/backgrounds/title", 90, ".png", 5)
    love.update = titleScreenUpdate
    love.draw = titleScreenDraw
    love.keypressed = titleScreenKeyPressed
end

function configUpdate()
end

function configDraw()
    love.graphics.draw(configEntryImage, 0, 0)
    for i = 1, currentConfigIdx - 1 do
        local idx = 0
        configInput[i]:gsub(".", function (ch)
            local xo, yo = unpack(configEntryLines[i])
            x = xo + (idx * (keyboardPrinter.w * configInputScale))
            y = yo
            keyboardPrinter:draw(ch, x, y, configInputScale)
            idx = idx + 1
        end)
    end
    local idx = 0
    currentInput:gsub(".", function (ch)
        local xo, yo = unpack(configEntryLines[currentConfigIdx])
        x = xo + (idx * (keyboardPrinter.w * configInputScale))
        y = yo
        keyboardPrinter:draw(ch, x, y, configInputScale)
        idx = idx + 1
    end)
end

function configTextInput(t)
    if #currentInput < maxConfigInput then
        if getConfigInitialized and keyboardPrinter.quads[t] ~= nil then
            currentInput = currentInput .. string.lower(t)
        end
    end
    if not getConfigInitialized then
        getConfigInitialized = true
    end
end

function configKeypressed(key)
    if key == "backspace" then
        local byteoffset = utf8.offset(currentInput, -1)

        if byteoffset then
            currentInput = string.sub(currentInput, 1, byteoffset - 1)
        end
    end

    if key == "return" then
        currentConfigIdx = currentConfigIdx + 1
        table.insert(configInput, currentInput)
        currentInput = ""
    end

    if currentConfigIdx > 3 then
        initGame()
    end
end

function getConfig()
    getConfigInitialized = false
    love.quit = nil
    love.update = configUpdate
    love.draw = configDraw
    love.keypressed = configKeypressed
    love.textinput = configTextInput
    love.keyboard.setKeyRepeat(true)
    configEntryImage = newImage("sprites/configentry.png")
    configInput = {}
    currentInput = ""
    currentConfigIdx = 1
    configInputScale = 4
    maxConfigInput = 32
    configEntryLines = {
        [1] = {200, 400},
        [2] = {200, 640},
        [3] = {200, 880}
    }
    keyboardPrinter = MultiImageIndexer("sprites/keyboard.png", 12, 12, {
        "1",
        "2",
        "3",
        "4",
        "5",
        "6",
        "7",
        "8",
        "9",
        "0",
        "q",
        "w",
        "e",
        "r",
        "t",
        "y",
        "u",
        "i",
        "o",
        "p",
        "a",
        "s",
        "d",
        "f",
        "g",
        "h",
        "j",
        "k",
        "l",
        "up",
        "z",
        "x",
        "c",
        "v",
        "b",
        "n",
        "m",
        "_",
        ".",
        "@"
    })
end

function initGame()
    username = configInput[1]
    local servername = configInput[2]
    local port = configInput[3]
    connectServer(servername, port, username)
    love.keypressed = nil
    love.textinput = nil
    love.quit = gameQuit
    love.update = gameUpdate
    love.draw = gameDraw
    gamestate = {
        players = {},
        shots = {}
    }

    npcs = {}

    love.mouse.setGrabbed(true)
    local newCursor = love.mouse.newCursor(love.image.newImageData("sprites/cursor.png"), 32.5, 32.5)
    love.mouse.setCursor(newCursor)

    min_dt = 1/60
    next_time = love.timer.getTime()


    cam = gamera.new(0, 0, 7680, 1920)
    cam:setWindow(0, 0, 1920, 1080)
    cam:setScale(2.0)
    x = 0
    y = 0


    map = Map(
    {"map-collision"},
    {"map-damage"},
    {
        "map-background",
        "map-scenery"
    },
    {
        --{468, 826},
        ----{540, 612},
        --{2292, 1164},
        --{3000, 792},
        {2388, 888},
        --{1588, 480},
        --{3444, 550},
        --{4098, 782},
        --{5034, 522},
        --{5820, 840},
        --{6440, 720},
        --{7446, 924}
    }
    )
    newPlayer = newYellowPlayer
    player = newPlayer(username)
    player.hp = 0
end

function love.load()
    love.graphics.setDefaultFilter('nearest', 'nearest')
    originalCursor = love.mouse.getCursor()
    love.graphics.setBackgroundColor(0x1A, 0x0D, 0x24)
    love.window.setMode(1920, 1080)
    Object = require("lib/classic")
    require("CollisionObject")
    require("MultiImageAnimation")
    require("Map")
    require("lib/helpers")
    gamera = require("lib/gamera")
    require("Player")
    require("NonPlayerCharacter")
    require("lib/vector")
    utf8 = require("utf8")
    sock = require("lib/sock/sock")
    bitser = require("lib/bitser/bitser")
    json = require("lib/json")
    titleScreenInit()
end

function gameQuit()
    love.mouse.setCursor(originalCursor)
    love.mouse.setGrabbed(false)
end

function gameUpdate(dt)
    next_time = next_time + min_dt
    dx, dy = player:update(dt, map)
    if player.hp == 0 then
        player:die()
        if player.isDead then
            player = newPlayer(username)
        end
    end

    for _, plyr in pairs(gamestate.players) do
        if plyr.name ~= username then
            if not npcs[plyr.name] then
                npcs[plyr.name] = newNPC(plyr.name, plyr.x, plyr.y)
            end
            npcs[plyr.name].x = plyr.x
            npcs[plyr.name].y = plyr.y
            npcs[plyr.name]:setAnimation(plyr.animation)
            npcs[plyr.name].isDead = plyr.dead
            npcs[plyr.name].jumping = plyr.jump
            npcs[plyr.name].direction = plyr.direction
            npcs[plyr.name].hp = plyr.hp
            npcs[plyr.name]:update(dt)
        else
            if plyr.hp < player.hp then
                for i=0,player.hp-plyr.hp,1 do
                    player:takeDamage()
                end
            end
        end
    end

    for name, plyr in pairs(npcs) do
        if not gamestate.players[name] then
            npcs[name] = nil
        end
    end

    client:update()
    assert(client:isConnected() or client:isConnecting(), "Error: disconnected from server")
end

function gameDraw()
    cam:draw(function (l, t, w, h)
        map:draw()
        player:draw()
        for _, p in pairs(npcs) do
            p:draw()
        end
        local r, g, b, a = love.graphics.getColor()
        local lw = love.graphics.getLineWidth()
        love.graphics.setColor(unpack{229, 38, 38})
        love.graphics.setLineWidth(8)
        for _, shot in pairs(gamestate.shots) do
            if shot.shooter ~= username then
                love.graphics.line(unpack(shot.shot))
            end
        end
        love.graphics.setColor(r, g, b, a)
        love.graphics.setLineWidth(lw)
    end)

    local cur_time = love.timer.getTime()
    if next_time <= cur_time then
        next_time = cur_time
        return
    end

    love.timer.sleep(next_time - cur_time)
end
