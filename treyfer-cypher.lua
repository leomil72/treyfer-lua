--[[
  TREYFER block algorithm implemented in Lua
  written by Leonardo Miliani (2022)
  Works with Lua 5.4
  Released under the Creative Commons SA-NC-BY 4.0 or later

  Version 1.0 - 2022/11/27
  Version 1.1 - 2022/12/31

  ----------------------------------------------------------

  The Treyfer cypher was invented in 1997. It was primarily
  used to encrypt data in smart card applications. It has
  a key size and block size of 64 bits each, thus it is not
  robust enough for criptographically secure operations but
  it is a good algorithm to procted non-top secret info...

  The algorithm works by taking a string or a table as input
  and return an encrypted table. Input table must start at
  element #0.

  ---------------------------------------------------------

  The cipher must output these results when using 32 rounds
  and text & key equal to 'AAAAAAAA':
  plaintext: 4141414141414141
  key: 4141414141414141
  ref. encrypted: 19029D7CD6ACC58E
  encrypted: 19029D7CD6ACC58E
  decrypted: 4141414141414141

]]

local tryefer = require 'treyfer'


-- print a text using hex representation
function printhex(txt)
  local text = txt
  if type(text) == 'string' then  -- transform string into a table
    text = str2tbl(text)
  end
  local output = ''
  for i = 0, #text do
    output = output .. string.format("%02X", string.byte(text[i]))
  end
  return output
end


-- from string to table
function str2tbl(str)
  local str = str
  local t = {}
  if type(str) == 'string' then
    for i = 1, #str do
      t[i - 1] = str:sub(i, i)
    end
  elseif type(str) == 'table' then
    -- check if the table starts at '0'
    local s = str[i] == nil and 1 or 0
    for i = (1 - s), #str do
      t[i] = str[i]
    end
  else
    t = ''
  end
  return t
end


-- reference
local text  = 'AAAAAAAA' --plain text
local text2 = 'AAAAAAAA' --secondary plain text
local key   = 'AAAAAAAA' --key

print('plaintext:..... ' .. printhex(text))
print('key:........... ' .. printhex(key))

text = treyfer.ref_encrypt(str2tbl(text), str2tbl(key))
print('ref. encrypted: ' .. printhex(text))

text2 = treyfer.encrypt(str2tbl(text2), str2tbl(key))
print('encrypted:..... ' .. printhex(text2))

text2 = treyfer.decrypt(text2, str2tbl(key))
print('decrypted:..... ' .. printhex(text2))

-- -[[ 
-- padding to fill up to blocks whose lenght is modulo 8
function padding(str)
  if #str % 8 == 0 then
    str = str
  else
    str = str .. string.rep(' ', 8 - (#str % 8))
  end
  return str
end
  
-- interactive mode
print()
io.write('Insert a text: ')
local inp = io.read()
if inp ~= '' then
  -- if text is not empty, then ask a key
  io.write('Key: ')
  local key = io.read()
  -- empty key? leave
  if key == '' then os.exit() end
  -- keys exactly 8 chars lenght
  if #key > 8 then
    key = key:sub(1, 8)
  elseif #key < 8 then
    key = padding(key)
  end
  --pad the text so that lenght is modulo 8
  local inptxt = inp
  inptxt = padding(inptxt)

  local tb = {}
  local res = {}
  -- divide the text into blocks of 8
  for i = 1, #inptxt // 8 do
    tb = {}
    local p = (i - 1) * 8
    -- copy the block into a temp. table starting from element #0
    for j = 1, 8 do
      tb[j - 1] = inptxt:sub(p + j, p + j)
    end
    -- encrypt the block
    local t = treyfer.encrypt(tb, str2tbl(key))
    -- put the results into a table
    for i = 0, 7 do
      res[p + i] = t[i]
    end
  end
  print('Encryption: ' .. printhex(res))
  -- decryption
  io.write('Decryption: ')
  -- divide the encrypted text into blocks of 8 chars
  for i = 1, (#res + 1) // 8 do
    tb = {}
    -- copy the block into a temp. table starting from element #0
    for j = 0, 7 do
      tb[j] = res[(i - 1) * 8 + j]
    end
    -- decrypt the block
    local t = treyfer.decrypt(tb, str2tbl(key))
    -- print the block
    for i = 0, 7 do
      io.write(t[i])
    end
  end
  print()
end
--]]