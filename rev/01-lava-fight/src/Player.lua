Player = CollisionObject:extend()

function inRange(i, min, max) 
    if i >= min and i <= max then
        return true
    end
    return false
end

function Player:new(name, image, x, y, walkAnimation, stillAnimation, jumpAnimation, fireAnimation, deathAnimation, cam, shotColor)
    self.image = image
    self.x = x
    self.y = y
    Player.super:new(self.image, self.x, self.y)
    self.walkAnimation = walkAnimation
    self.stillAnimation = stillAnimation
    self.jumpAnimation = jumpAnimation
    self.fireAnimation = fireAnimation
    self.deathAnimation = deathAnimation
    self.networkFireVectors = {}

    self.jumping = false
    self.walking = false
    self.jumpTimer = 0
    self.currentAnimation = self.stillAnimation
    self.primaryScaleFactor = 1
    self.scaleFactor = self.primaryScaleFactor
    self.maxhp = 3
    self.hp = self.maxhp
    self.gracePeriod = 3
    self.isDead = false
    self.runSpeed = 128
    self.heartoffsetx = 24
    self.heartoffsety = 24
    self.heartscalefactor = .5
    self.jumpSpeed = 2
    self.jumpTimeMax = 8
    self.vyGravity = 0
    self.gravity = 320
    self.cam = cam
    self.direction = "left"
    self.w = self.w * self.primaryScaleFactor
    self.h = self.h * self.primaryScaleFactor
    self.onGround = true
    self.damageCooldown = 0
    self.firing = false
    self.fireTimer = 0
    self.upDamageTimer = 0
    self.downDamageTimer = 0
    self.leftDamageTimer = 0
    self.rightDamageTimer = 0
    self.fireVectors = {}
    self.shotColor = shotColor
    self.heartfull = love.graphics.newImage("sprites/heart-full.png")
    self.heartempty = love.graphics.newImage("sprites/heart-empty.png")
end

function Player:fire()
    if self.fireTimer <= 0 then
        local selfx, selfy = self.x + (self.w / 2), self.y + (self.h / 2)
        local mousex, mousey = love.mouse.getPosition()
        local camx, camy = self.cam:getPosition()
        local _, _, camw, camh = self.cam:getWindow()
        local camnormalizex, camnormalizey = camx - selfx, camy - selfy
        local actualclickx, actualclicky = mousex - (camw / 2) + camnormalizex + 2 * (camnormalizex), mousey - (camh / 2) + 2 * (camnormalizey)
        local shotVector = Vector2(actualclickx, actualclicky)
        local _, _, worldw, _ = self.cam:getWorld()
        shotVector = shotVector:resize(worldw)
        table.insert(self.fireVectors, shotVector:getQuadAt(self.x + (self.w / 2), self.y + (self.h / 2)))
        self.firing = true
        self.fireTimer = .1
    end
end

function Player:getMoveButtons()
    local l, r, u = false, false, false
    if love.keyboard.isDown("a") then
        l = true
    end
    if love.keyboard.isDown("d") then
        r = true
    end
    if love.keyboard.isDown("w") then
        u = true
    end
    if love.keyboard.isDown("q") then
        self:die()
    end
    return l, r, u
end

function Player:processJump(dt, initiateJump)
    local dy = 0
    if self.onGround and initiateJump then
        if not self.jumping then
            self.jumpTimer = self.jumpTimeMax
            self.jumping = true
        end
    end

    if self.jumping then
        self.jumpTimer = self.jumpTimer - dt
        dy = -self.jumpSpeed
    end

    if (self.jumping and not initiateJump) or (self.jumping and self.jumpTimer <= 0) then
        self.jumping = false
        self.jumpTimer = 0
        self.vyGravity = 0
    end

    return dy
end

function Player:processGravity(dt)
    self.vyGravity = self.vyGravity + (self.gravity * dt)
    return -self.vyGravity * dt
end


function Player:processPhysics(dt, map)
    local l, r, u = self:getMoveButtons()
    local g = false

    local dx = 0
    local dy = 0

    if l then
        dx = -self.runSpeed * dt
        self.walking = true
        self.direction = "left"
    end
    if r then
        dx = self.runSpeed * dt
        self.walking = true
        self.direction = "right"
    end

    if not r and not l then
        self.walking = false
    end

    dy = self:processJump(dt, u)
   if not self.jumping then
        dy = dy - self:processGravity(dt)
        if dy ~= 0 then
            g = true
        end
    end

    local collision, damage = map:checkCollisionDamage(self)
    local left, right, up, down = false, false, false, false
    local leftd, rightd, upd, downd = false, false, false, false

    local spriteIdx = math.floor(self.currentAnimation.currentTime / self.currentAnimation.duration * #self.currentAnimation.quads) + 1
    local border = self:getBorder(self.currentAnimation.spriteSheet, self.currentAnimation.quads[spriteIdx])
    local results = map:getBorderCollision(self:getBorder(border))
    self.damageMovementDirection = {}
    for _, result in pairs(results) do
        if result.left.collision then
            left = true
        end
        if result.left.damage then
            leftd = true
            self:takeDamage()
            self.leftDamageTimer = .3
        end
        if self.leftDamageTimer >= 0 then
            dx = dx + 6
            self.leftDamageTimer = self.leftDamageTimer - dt
        end
        if result.right.collision then
            right = true
        end
        if result.right.damage then
            rightd = true
            self:takeDamage()
            self.rightDamageTimer = .3
        end
        if self.rightDamageTimer >= 0 then
            dx = dx - 6
            self.rightDamageTimer = self.rightDamageTimer - dt
        end
        if result.top.collision then
            up = true
        end
        if result.top.damage then
            upd = true
            self:takeDamage()
            self.upDamageTimer = .3
        end
        if self.upDamageTimer >= 0 then
            dy = dy + 6
            self.upDamageTimer = self.upDamageTimer - dt
        end
        if result.bottom.collision then
            down = true
            self.onGround = true
        else
            self.onGround = false
        end
        if result.bottom.damage then
            downd = true
            self:takeDamage()
            self.downDamageTimer = .3
        end
        if self.downDamageTimer >= 0 then
            dy = dy - 6
            self.downDamageTimer = self.downDamageTimer - dt
            if self.downDamageTimer <= 0 then
                self.vyGravity = 0
            end
        end
    end


    if left and dx < 0 then
        dx = 0
    end
    if right and dx > 0 then
        dx = 0
    end
    if up and dy < 0 then
        dy = 0
    end
    if down and dy > 0 then
        dy = 0
        self.vyGravity = 0
    end
    if self.damageCooldown >= 0 then
        self.damageCooldown = self.damageCooldown - dt
    end
    self.x = self.x + dx
    self.y = self.y + dy
    return dx, dy
end

function Player:takeDamage()
    if self.damageCooldown <= 0 then
        if self.gracePeriod <= 0 then
            --self.hp = self.hp - 1
            self.hp = self.hp + 1
            self.damageCooldown = .5
        end
    end
    if self.jumping then
        self.jumping = false
        self.jumpTimer = 0
        self.vyGravity = 0
    end
end

function Player:getCamPos()
    return self.x + (self.w / 2), self.y +( self.h / 2)
end

function Player:doAnimation()
    if self.currentAnimation.currentTime > self.currentAnimation.duration then
        self.currentAnimation.currentTime = 0
    end

    local spriteIdx = math.floor(self.currentAnimation.currentTime / self.currentAnimation.duration * #self.currentAnimation.quads) + 1

    local xOffset = 0
    local yOffset = 0
    if self.direction == "right" then
        self.scaleFactor = self.primaryScaleFactor
        xOffset = 0
        if self.currentAnimation == self.deathAnimation then
            xOffset = -64
            yOffset = -32
        end
    elseif self.direction == "left" then
        self.scaleFactor = -1 * self.primaryScaleFactor
        xOffset = math.abs(self.scaleFactor) * self.w
        if self.currentAnimation == self.deathAnimation then
            xOffset = 64
            yOffset = -32
        end
    end
    
    love.graphics.draw(self.currentAnimation.spriteSheet, self.currentAnimation.quads[spriteIdx], self.x + xOffset, self.y + yOffset, 0, self.scaleFactor, math.abs(self.scaleFactor))
    local lw = love.graphics.getLineWidth()
    love.graphics.setLineWidth(4)
    local r, g, b, a = love.graphics.getColor()
    love.graphics.setColor(unpack(self.shotColor))
    for _, vec in pairs(self.fireVectors) do
        love.graphics.line(unpack(vec))
        table.insert(self.networkFireVectors, vec)
    end
    self.fireVectors = {}
    love.graphics.setLineWidth(lw)
    love.graphics.setColor(r, g, b, a)
end

function Player:animationUpdate(dt)
    self.currentAnimation.currentTime = self.currentAnimation.currentTime + dt
    if self.currentAnimation.currentTime >= self.currentAnimation.duration then
        self.currentAnimation.currentTime = self.currentAnimation.currentTime - self.currentAnimation.duration
    end
end

function Player:deathAnimationUpdate(dt)
    self.currentAnimation.currentTime = self.currentAnimation.currentTime + dt
end

function Player:dieUpdate(dt, map)
    self:deathAnimationUpdate(dt)
    if self.currentAnimation.currentTime >= self.currentAnimation.duration then
        self.isDead = true
    end
end

function Player:die()
    self.hp = 0
    self.primaryScaleFactor = 1/2
    self.currentAnimation = self.deathAnimation
    self.update = self.dieUpdate
end

function Player:update(dt, map)
    if self.jumping then
        self.currentAnimation = self.jumpAnimation
    elseif self.walking then
        self.currentAnimation = self.walkAnimation
    else 
        self.currentAnimation = self.stillAnimation
    end

    if love.mouse.isDown(1) then
        self:fire()
    end

    if self.gracePeriod > 0 then
        self.gracePeriod = self.gracePeriod - dt
    end

    if self.firing then
        if not self.currentAnimation == self.jumpAnimation then
            self.currentAnimation = self.fireAnimation
        end
        self.fireTimer = self.fireTimer - dt
        if self.fireTimer <= 0 then
            self.firing = false
        end
    end

    self:animationUpdate(dt)
    self.cam:setPosition(self:getCamPos())
    local dx, dy = self:processPhysics(dt, map)
    return dx, dy
end

function Player:getX()
    return self.x
end

function Player:getY()
    return self.y
end

function Player:drawHearts()
    
    x1, y1 = self.cam:getVisibleCorners()
    for i=0,self.hp - 1,1 do
        love.graphics.draw(self.heartfull, x1 + self.heartoffsetx + (self.heartfull:getWidth() * i), y1 + self.heartoffsety, 0, self.heartscalefactor, self.heartscalefactor)
    end
    for i=self.hp,self.maxhp - 1,1 do
        love.graphics.draw(self.heartempty, x1 + self.heartoffsetx + (self.heartfull:getWidth() * i), y1 + self.heartoffsety, 0, self.heartscalefactor, self.heartscalefactor)
    end
end

function Player:draw()
    self:doAnimation()
    self:drawHearts()
end


function Player:getNetworkUpdate(name)
    local update = {
        name,
        self.x,
        self.y,
        self.w,
        self.h,
        self.currentAnimation.name,
        self.isDead,
        self.jumping,
        self.direction,
        self.hp,
        {}
    }
    for _, vec in pairs(self.networkFireVectors) do
        table.insert(update[11], vec)
    end
    self.networkFireVectors = {}
    return update
end
