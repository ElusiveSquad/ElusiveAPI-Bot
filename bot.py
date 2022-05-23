from array import array
from codecs import StreamWriter
from xmlrpc.client import TRANSPORT_ERROR
import discord
from discord.ext import commands
import requests
import json 
from datetime import datetime

from modules.api import addApiKey, createAccount, getJsonFromObj, getServers, sendAttack, stopAttack

bot = commands.Bot(command_prefix=getJsonFromObj("Discord","Bot Prefix"), case_insensitive=True,description="Na", self_bot=False)

bot.remove_command("help")

def whitelistUser(id, name) -> str:
    try:

        file = open('config/auth.json')
        _json = json.load(file)
        file.close()

        if not id in _json["WhitelistIds"]:
            _json["WhitelistIds"].append(id)
            _json["WhitelistCombos"].append(f"{id} - {str(name)}")
            _json = json.dumps(_json,sort_keys=True, indent=4)
            f = open('config/auth.json', 'r+')
            f.truncate(0)
            f.write(str(_json))
            f.close()
            return "Whitelisted user"
        else:
            return "User already whitelisted"
    except Exception as e:
        return "Error while whitelisting user"


def isAdmin(id):

    f = open('config/auth.json')
    _json = json.load(f)
    f.close()
    
    return id in _json["Administrators"]
    
def getIpInfo(ip) -> list:

    keys = []
    values = []

    blacklist = ["readme","anycast","timezone"]
    
    req = requests.get(f"https://ipinfo.io/{ip}/json").text 
    
    req_json = json.loads(req)

    if req_json.get("status"):
        return ["Failure: True"],[f"Status code: {req_json['status']}"]

    for i in req_json:
        if not i in blacklist:
            keys.append(i)
            values.append(req_json[i])
    
    return keys,values
def unwhitelistUser(id) -> str:
    try:         
        file = open('config/auth.json')
        _json = json.load(file)
        file.close()

        if id in _json["WhitelistIds"]:
            _json["WhitelistIds"].remove(id)
            for x in _json["WhitelistCombos"]:
                if str(x[0:18]) == str(id):
                    _json["WhitelistCombos"].remove(x)

            _json = json.dumps(_json,sort_keys=True, indent=4)
            f = open('config/auth.json', 'r+')
            f.truncate(0)
            f.write(str(_json))
            f.close()
            return "Unwhitelisted user"
        else:
            return "User not whitelisted"
    except Exception as e:
        return "Error unwhitelisting user"

def hasPermission(ctx) -> bool:
    try:
        id = ctx.author.id
        file = open('config/auth.json')
        json_content = json.load(file)
        file.close()

        if id in json_content["WhitelistIds"]:
            return True
        else:
            return False
    except Exception as e:
        return False

def returnWhitelist() -> list:

    wl = []

    wl_list = open('config/auth.json')
    json_wl = json.load(wl_list)
    wl_list.close()
    
    for i in json_wl["WhitelistCombos"]:
        wl.append(i)
    return wl 

@bot.event                    
async def on_ready():
    print("started")

@bot.command()
async def genkey(ctx, member: discord.Member):
    if hasPermission(ctx):
        key = addApiKey(getServers()[0],getJsonFromObj("Api","Administrator Key"))

        if key == "Failure generating API key.":
            await ctx.send("Error generating API key.")
            return 

        try:

            embed = discord.Embed(title="Elusive - API", color=discord.Color.from_rgb(0, 64, 255))
            embed.add_field(name="```Created by```", value=f"```{ctx.author}```", inline=True)
            embed.add_field(name="```Logging status```", value="```Success```", inline=True)
            embed.add_field(name="```Key```", value=f"```{key}```", inline=False)
            embed.add_field(name="```Date Created```", value=f"```{datetime.today().strftime('%Y-%m-%d')}```", inline=False)


            embedPublic = discord.Embed(title="Elusive - API", color=discord.Color.from_rgb(0, 64, 255))
            embedPublic.add_field(name="```Created by```", value=f"```{ctx.author}```", inline=True)
            embedPublic.add_field(name="```Logging status```", value="```Success```", inline=True)
            embedPublic.add_field(name="```Key sent to user```", value=f"```fix\nTrue```", inline=False)
            embedPublic.add_field(name="```Date Created```", value=f"```{datetime.today().strftime('%Y-%m-%d')}```", inline=False)

            await member.send(embed=embed)
            await ctx.send(embed=embedPublic)
        except Exception as e:
            await ctx.send("Failed to send user their API Key.")

    else:
        await ctx.send(f"<@!{ctx.author.id}> You don't have permission to generate API Keys.")
 
@bot.command()
async def createaccount(ctx, member: discord.Member, username: str):
    if hasPermission(ctx):
        credentials = createAccount(getServers()[0],getJsonFromObj("Api","Administrator Key"),username)

        if credentials == "Failure creating account.":
            await ctx.send("Failure creating account")
            return 
        
        username = credentials[0]
        password = credentials[1]
        try:
            embed = discord.Embed(title="Elusive - API", color=discord.Color.from_rgb(0, 64, 255))
            embed.add_field(name="```Your account was created by```", value=f"```{ctx.author}```", inline=True)
            embed.add_field(name="```Logging status```", value="```Success```", inline=True)
            embed.add_field(name="```Username```", value=f"```{username}```", inline=False)
            embed.add_field(name="```Password```", value=f"```{password}```", inline=True)
            await member.send(embed=embed)
        except Exception as e:
            await ctx.send("Failure direct messaging user.")
            return
        embed = discord.Embed(title="Elusive API", color=discord.Color.from_rgb(0, 64, 255))
        embed.set_image(url="https://cdn.discordapp.com/attachments/968494274096300073/968519373868400660/img.jpg")
        embed.add_field(name="```API Response```", value=f"```Account created and user was notified.```", inline=True)
        await ctx.send(embed=embed)
    else:
        await ctx.send(f"<@!{ctx.author.id}> You don't have permission to create accounts.")

@bot.command()
async def attack(ctx, ip: str, port: int, time: int, method: str):
    if hasPermission(ctx):
        attack_sent = sendAttack(getServers()[0],getJsonFromObj("Api","Attack key"),ip,port,time,method)
        if attack_sent:
            embed = discord.Embed(title="Elusive - API", color=discord.Color.from_rgb(0, 64, 255))
            embed.add_field(name="```Target```", value=f"```{ip}```", inline=False)
            embed.add_field(name="```Port```", value=f"```{port}```", inline=True)
            embed.add_field(name="```Time```", value=f"```{time}```", inline=True)  
            embed.add_field(name="```Method```", value=f"```{method.upper()}```", inline=False)    
            embed.set_image(url="https://cdn.discordapp.com/attachments/971538759516581888/971585692016709663/ezgif.com-gif-maker_1.gif")
            await ctx.send(embed=embed)
        else:
            await ctx.send("Failure while sending attack.")
    else:
        await ctx.send("You don't have permission to run this command")

@bot.command()
async def stop(ctx, ip):
    if(hasPermission(ctx)):
        stopped_attack = stopAttack(getServers()[0],getJsonFromObj("Api","Attack key"),ip)
        embed = discord.Embed(title="Elusive - API", color=discord.Color.from_rgb(0, 64, 255))
        embed.add_field(name="```Target```", value=f"```{ip}```", inline=False) 
        embed.add_field(name="```Attack Stopped```", value=f"```fix\n{stopped_attack}```", inline=False) 
        await ctx.send(embed=embed)
    else:
        await ctx.send(f"<@!{ctx.author.id}> You don't have permission to stop attacks")

@bot.command()
async def whitelist(ctx, member: discord.Member):
    if ctx.author.id == 960160824503185541 or ctx.author.id == 911931630027964447:
        whitelisted = whitelistUser(member.id, member)
        embed = discord.Embed(title="Elusive - API", color=discord.Color.from_rgb(0, 64, 255))
        embed.add_field(name="```User whitelisted```", value=f"```{member}```", inline=False) 
        embed.add_field(name="```Response```", value=f"```fix\n{whitelisted}```", inline=False) 
        await ctx.send(embed=embed)
    else:
         await ctx.send("You can't whitelist users.")

@bot.command()
async def methods(ctx):
    if(hasPermission(ctx)):
        embed = discord.Embed(color=discord.Color.from_rgb(0, 64, 255))
        embed.add_field(name="```L4 Methods```", value=f"```\nUDP-KILL\nUDP-FLOOD\nHOME-DROP\nUDP-DIRECT\nVPN-DOWN\nHOME-FREEZE```", inline=True) 
        embed.add_field(name="```L7 Methods```", value=f"```\nSOCKET-GET\nSOCKET-FLOOD\nHTTP-SPAM\nHTTP-FLOOD```", inline=True) 
        embed.add_field(name="```Bypass Methods```", value=f"```\nUDP-BYPASS\nTCP-BYPASS\nOVH-DOWN\nOVH-DROP```", inline=True) 

        await ctx.send(embed=embed)

@bot.command()
async def unwhitelist(ctx, member: discord.Member):
    if ctx.author.id == 960160824503185541 or ctx.author.id == 911931630027964447:
        unwhitelisted = unwhitelistUser(member.id)
        embed = discord.Embed(title="Elusive - API", color=discord.Color.from_rgb(0, 64, 255))
        embed.add_field(name="```User unwhitelisted```", value=f"```{member}```", inline=False) 
        embed.add_field(name="```Response```", value=f"```fix\n{unwhitelisted}```", inline=False) 
        await ctx.send(embed=embed)
    else:
         await ctx.send("You can't unwhitelist users.")

@bot.command()
async def wl(ctx):
    if(hasPermission(ctx)):

        wl_ids = returnWhitelist()
        str_embed = ""
        embed = discord.Embed(title="Elusive - API", color=discord.Color.from_rgb(0, 64, 255))
        
        for i in wl_ids:
            str_embed += f"{i}\n"
        embed.add_field(name="```Whitelisted Ids```",value=f"```{str_embed}```",inline=False)
        await ctx.send(embed=embed)
    else:
        await ctx.send("You don't have permission to use this command")

@bot.command()
async def lookup(ctx, ip):
    if(hasPermission(ctx)):
        embed = discord.Embed(title="Elusive - API", color=discord.Color.from_rgb(0, 64, 255))
        k,v = getIpInfo(ip)
        for i in range(len(k)):
            embed.add_field(name=f"```{k[i].capitalize()}```", value=f"```{v[i]}```", inline=False) 
        await ctx.send(embed=embed)
    else:
        await ctx.send(f"<@!{ctx.author.id}> You don't have permission to use this command.")
        
@bot.command()
async def verify(ctx, member: discord.Member):
    if(isAdmin(ctx.author.id)):
        role_json = open('config/auth.json')
        _json = json.load(role_json)
        role_json.close()
        
        try:
            verification_role = ctx.guild.get_role(_json["Roles"]["On_Admin_Verified_Role"])
            await member.add_roles(verification_role)
            await ctx.send("Verified user")
        except Exception as e:
            await ctx.send("Failed to give user verification role.")
    else:
        await ctx.send("You cant verify users.")
bot.run(getJsonFromObj("Discord","Bot Token"),bot=True)
