NonPlayerCharacter = CollisionObject:extend()

function inRange(i, min, max) 
    if i >= min and i <= max then
        return true
    end
    return false
end

function NonPlayerCharacter:new(name, image, x, y, walkAnimation, stillAnimation, jumpAnimation, fireAnimation, deathAnimation, shotColor)
    self.name = name
    self.image = image
    self.x = x
    self.lastx = x
    self.y = y
    NonPlayerCharacter.super:new(self.image, self.x, self.y)
    self.walkAnimation = walkAnimation
    self.stillAnimation = stillAnimation
    self.jumpAnimation = jumpAnimation
    self.fireAnimation = fireAnimation
    self.deathAnimation = deathAnimation

    self.jumping = false
    self.walking = false
    self.jumpTimer = 0
    self.currentAnimation = self.stillAnimation
    self.primaryScaleFactor = 1
    self.scaleFactor = self.primaryScaleFactor
    self.hp = 3
    self.isDead = false
    self.runSpeed = 256
    self.jumpSpeed = 6
    self.jumpCooldown = 2
    self.vyGravity = 0
    self.gravity = 320
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
end

function NonPlayerCharacter:takeDamage()
    if self.damageCooldown <= 0 then
        self.hp = self.hp - 1
        self.damageCooldown = .5
    end
    if self.jumping then
        self.jumping = false
        self.jumpTimer = 0
        self.vyGravity = 0
    end
end

function NonPlayerCharacter:doAnimation()
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
end

function NonPlayerCharacter:animationUpdate(dt)
    self.currentAnimation.currentTime = self.currentAnimation.currentTime + dt
    if self.currentAnimation.currentTime >= self.currentAnimation.duration then
        self.currentAnimation.currentTime = self.currentAnimation.currentTime - self.currentAnimation.duration
    end
end

function NonPlayerCharacter:deathAnimationUpdate(dt)
    self.currentAnimation.currentTime = self.currentAnimation.currentTime + dt
end

function NonPlayerCharacter:dieUpdate(dt, map)
    self:deathAnimationUpdate(dt)
    if self.currentAnimation.currentTime >= self.currentAnimation.duration then
        self.isDead = true
    end
end

function NonPlayerCharacter:die()
    self.primaryScaleFactor = 1/2
    self.currentAnimation = self.deathAnimation
    self.update = self.dieUpdate
end

function NonPlayerCharacter:setAnimation(name)
    if name == self.currentAnimation.name then
        return
    end

    if name == "walk" then
        self.currentAnimation = self.walkAnimation
    elseif name == "still" then
        self.currentAnimation = self.stillAnimation
    elseif name == "jump" then
        self.currentAnimation = self.jumpAnimation
    elseif name == "death" then
        self.currentAnimation = self.deathAnimation
    elseif name == "fire" then
        self.currentAnimation = self.fireAnimation
    end
end

function NonPlayerCharacter:update(dt)
    self:animationUpdate(dt)
    self.lastx = self.x
end

function NonPlayerCharacter:getX()
    return self.x
end

function NonPlayerCharacter:getY()
    return self.y
end

function NonPlayerCharacter:draw()
    self:doAnimation()
end
