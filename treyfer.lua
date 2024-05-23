
Treyfer = {}

local sbox = require 'sbox'
local NUMROUNDS = 32 --number of rounds


-- reference encryption
function Treyfer.ref_encrypt(txt, key)
  local txt = txt
  local key = key
  local t = string.byte(txt[0])

  for i = 0, 8 * NUMROUNDS - 1 do
    t = (t + string.byte(key[i % 8])) & 255
    t = (sbox[t] + string.byte(txt[(i + 1) % 8])) & 255
    t = ((t << 1) | (t >> 7)) & 255
    txt[(i + 1) % 8] = string.char(t)
  end
  return txt
end


-- encryption
function Treyfer.encrypt(txt, key)
  local txt = txt
  local key = key
  local t = string.byte(txt[0])
  for j = 0, NUMROUNDS - 1 do
    for i = 0, 7 do
      t = (t + string.byte(key[i])) & 255
      t = (sbox[t] + string.byte(txt[(i + 1) % 8])) & 255
      t = ((t<<1) | (t >> 7)) & 255
      txt[(i + 1) % 8] = string.char(t)
    end
  end
  return txt
end


-- decryption
function Treyfer.decrypt(txt, key)
  local txt = txt
  local key = key
  local top = 0
  local bottom = 0
  for j = 0, NUMROUNDS - 1 do
    for i = 7, 0, -1 do
      top = (string.byte(txt[i]) + string.byte(key[i])) & 255
      top = sbox[top]
      bottom = string.byte(txt[(i + 1) % 8])
      bottom = ((bottom >> 1) | (bottom << 7)) & 255
      txt[(i + 1) % 8] = string.char((bottom - top) & 255)
    end
  end
  return txt
end

return Treyfer