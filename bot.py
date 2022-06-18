# Bub's personal bot made by ᴿᵒᵉᵐɥɔʇıl⅁. Do not redistribute without my permission.
# You can contact me for getting your own bot. Or using Bub with your own name.
# Bub.exe V 2.0.2

""""
What's new?
- Made BuB a DDR (Discord Detection and Response)
- Fixed welcome message
- Added badlink database send

To do
- better names :)
- Add removelinks
- Add non duplicates
"""

import discord
from discord.ext import commands
from discord.utils import find
import random
from discord.utils import get
import datetime
import time
import json
from virustotal_python import Virustotal
from virustotal_python import VirustotalError
from pprint import pprint
from base64 import urlsafe_b64encode
import re

intents = discord.Intents.default()
intents.members = True

token = 'NzA4MzY0MDI5NDc0NjM1Nzg3.XrWRaQ.5hRRNZMewFhKBG2nl5PWV9RdcwY'
bot = commands.Bot(command_prefix='/bub ', intents=intents)

time_window_milliseconds = 4000
max_msg_per_window = 2
author_msg_times = {}

vtotal = Virustotal(API_KEY="4e0eff914204b2f7d5a3371b70f4d7f93f6c0a13d69fd96b499432c0922e7866", API_VERSION="v3")

# Start of the bot, it shows if the bot is online
@bot.event
async def on_ready():
    print('Logged in as')
    print(bot.user.name)
    print(bot.user.id)
    print('------')
    await bot.change_presence(activity=discord.Activity(type=discord.ActivityType.watching, name="Being build ^^"))
    # await bot.change_presence(activity=discord.Streaming(name="Art", url='https://www.twitch.tv/bubshoku/'))


# Send the file with all the blacklisted links
@bot.command(pass_context=True, brief='Show all blacklisted links')
async def list(ctx):
    modRole = discord.utils.get(ctx.guild.roles, name="GUNSH0KU POLICE")
    if modRole in ctx.author.roles:
        await ctx.send('Here is the database of the badlinks!', file=discord.File("badlinks.json"))
    else:
        await ctx.send('You arent allowed to use this command! Only people with <@&926070819464036383> can use this ;)')


# Add new domain/link to database
@bot.command(pass_context=True, brief='Blacklist links')
async def blacklist(ctx, *, arg):
    modRole = discord.utils.get(ctx.guild.roles, name="GUNSH0KU POLICE")
    if modRole in ctx.author.roles or ctx.author.id == 137229706146742272:
        f = open("badlinks.json")
        bad_link = json.load(f)
        bad_link["domains"].append(arg)
        with open("badlinks.json", "w") as f:
            json.dump(bad_link, f, indent=4)
        await ctx.send('Added link: ' + arg + ' to the blacklist!')
        f.close()
    else:
        await ctx.send('You arent allowed to use this command! Only people with <@&926070819464036383> can use this ;)')


# @bot.command(pass_context=True, brief='Remove links from blacklist')
# async def unlist(ctx, *, arg):
#     modRole = discord.utils.get(ctx.guild.roles, name="GUNSH0KU POLICE")
#     if modRole in ctx.author.roles:
#         bad_link.remove(str(arg))
#         await ctx.send('Removed link: ' + arg + ' from the blacklist!')
#     else:
#         await ctx.send('You arent allowed to use this command! Only people with <@&926070819464036383> can use this ;)')


# When someone says something respond back
@bot.event
async def on_message(message):
    # auto remove malicious links
    if message.author.id == bot.user.id:
        return

    msg_content = message.content.lower()
    f = open("badlinks.json")
    bad_link = json.load(f)

    if any(word in msg_content for word in bad_link["domains"]):
        channel = bot.get_channel(780866269024616459)
        user = message.author.id
        global author_msg_counts
        curr_time = datetime.datetime.now().timestamp() * 1000
        if not author_msg_times.get(user, False):
            author_msg_times[user] = []

        author_msg_times[user].append(curr_time)

        expr_time = curr_time - time_window_milliseconds

        expired_msgs = [
            msg_time for msg_time in author_msg_times[user]
            if msg_time < expr_time
        ]

        for msg_time in expired_msgs:
            author_msg_times[user].remove(msg_time)

        role = get(message.guild.roles, name="Muted")
        if len(author_msg_times[user]) > max_msg_per_window:
            await message.author.add_roles(role)
            await channel.send("Malicious link detected! By: " + str(user) + ". User has been Muted")

        await message.delete()
        await message.channel.send(
            "A malicious link was detected. I deleted it to keep the chat safe. This issue has been reported")
        await channel.send("Malicious link detected! By: " + str(user) + "<@&616235965937352704>")

    f.close()

    if 'https://' in msg_content:
        url = re.search(r'(https?://\S+)', msg_content).group()
        try:
            user = message.author.id
            # Send URL to VirusTotal for analysis
            print(url)
            resp = vtotal.request("urls", data={"url": url}, method="POST")
            # URL safe encode URL in base64 format
            # https://developers.virustotal.com/v3.0/reference#url
            url_id = urlsafe_b64encode(url.encode()).decode().strip("=")
            # Obtain the analysis results for the URL using the url_id
            analysis_resp = vtotal.request(f"urls/{url_id}")
            pprint(analysis_resp.object_type)
            pprint(analysis_resp.data["attributes"]["last_analysis_stats"])
            if analysis_resp.data["attributes"]["last_analysis_stats"]["malicious"] > 2:
                await message.delete()
                await message.channel.send(
                    "A malicious link was detected. I deleted it to keep the chat safe. This issue has been reported")
                channel = bot.get_channel(780866269024616459)
                await channel.send(
                    "Malicious link detected! By: " + str(user) + "<@&616235965937352704>. Posted link: " + url)
            else:
                print("False")
        except VirustotalError as err:
            print(f"An error occurred: {err}\nCatching and continuing with program.")

    # auto remove commands
    # if message.content.startswith('<@!708364029474635787> '):
    #     await message.delete()

    # Small conversation with bub
    # if message.content.startswith('Bub'):
    #     print('someone triggered me talking!')
    #     if message.content.startswith('Bub what'):
    #     await message.channel.send(':green_heart:')

    await bot.process_commands(message)


# Whitelist users
@bot.command(pass_context=True, brief='Whitelist an user to not get autobanned by me')
async def whitelist(ctx, *, arg):
    modRole = discord.utils.get(ctx.guild.roles, name="the manager")
    if modRole in ctx.author.roles:
        with open('whitelisted.txt', 'a') as f:
            f.write(str(arg))
            f.close()
        await ctx.send('Added user: ' + arg + ' to the whitelist do not forgot to unban them!')
    else:
        await ctx.send('You arent allowed to use this command! Only <@&630715988022788107> can use this ;)')


# removes whitelists
# @bot.command(pass_context=True)
# async def blacklist(ctx, *, arg):
#     modRole = discord.utils.get(ctx.guild.roles, name="the manager")
#     if modRole in ctx.author.roles:
#         with open('whitelisted.txt', 'a') as f:
#
#             f.close()
#         await ctx.send('Removed user: ' + arg + ' from the whitelist! Do not forget to ban them!')
#     else:
#         await ctx.send('You arent allowed to use this command! Only <@&630715988022788107> can use this ;)')

# Whenever a member joins Bub says random things to the user and bans them

# Ban fresh users that are less than 30 days old, unless they are whitelisted
# Welcome new users when they join
@bot.event
async def on_member_join(member):
    await bot.wait_until_ready()

    with open('whitelisted.txt', 'r') as f:
        if str(member.id) not in f.read() and time.time() - member.created_at.timestamp() < 2492000:
            reason = "Your account is too new"
            await member.ban(reason=reason)
            print("User banned:", member)
        else:
            pass

    channel = bot.get_channel(904723886036369451)
    guild = member.guild
    welcomeUserList = ["""Hiya {}, 
Welcome to {}! 
Me is bub, the main bot of this server. 
An edgy kids told me to tell you that you can get some extra roles by checking <#646483216370368512>. 
And make sure to read the server rules <#612258216591622145> so you don’t get swatted! 
This server is pretty pogu so if you wanna show a nice flex, consider boosting it :>!
Enjoy your stay!""",
                       """Ooooh! I know this one! {}, you tried to be sneaky, huh?
Well I’m glad you made it over to {}! 
We’ve got custom roles check them out at: <#646483216370368512>.
Also, you should probs read them rules <#612258216591622145> to increase your knowledge! 
Happy to assist you! Enjoy the stay homie :green_heart:"""]
    welcomeUserListRandom = random.choice(welcomeUserList)
    message = str(welcomeUserListRandom).format(member.mention, "**GUNSH0KU was here.**")
    await channel.send(file=discord.File("bub_lurk_export.png"), delete_after=5)
    await channel.send(message, delete_after=60)


# Message when she joins the server. Sadly this is one time only :(
@bot.event
async def on_guild_join(guild):
    general = find(lambda x: x.name == 'general', guild.text_channels)
    if general and general.permissions_for(guild.me).send_messages:
        await general.send('Hiya! Guess who finally made it to {}? That’s right. One and only, bub!'.format(guild.name))


# -----------Commands-----------
#Fetch userinfo
@bot.command(pass_context=True, brief='Get information on user')
async def userinfo(ctx, *, user: discord.Member = None):
    modRole = discord.utils.get(ctx.guild.roles, name="GUNSH0KU POLICE")
    if modRole in ctx.author.roles:
        if user is None:
            user = ctx.author      
        date_format = "%a, %d %b %Y %I:%M %p"
        embed = discord.Embed(color=0xdfa3ff, description=user.mention)
        embed.set_author(name=str(user), icon_url=user.avatar_url)
        embed.set_thumbnail(url=user.avatar_url)
        embed.add_field(name="Joined", value=user.joined_at.strftime(date_format))
        members = sorted(ctx.guild.members, key=lambda m: m.joined_at)
        embed.add_field(name="Join position", value=str(members.index(user)+1))
        embed.add_field(name="Registered", value=user.created_at.strftime(date_format))
        if len(user.roles) > 1:
            role_string = ' '.join([r.mention for r in user.roles][1:])
            embed.add_field(name="Roles [{}]".format(len(user.roles)-1), value=role_string, inline=False)
        perm_string = ', '.join([str(p[0]).replace("_", " ").title() for p in user.guild_permissions if p[1]])
        embed.add_field(name="Guild permissions", value=perm_string, inline=False)
        embed.set_footer(text='ID: ' + str(user.id))
        return await ctx.send(embed=embed)
    else:
        await ctx.send('You arent allowed to use this command! Only people with <@&926070819464036383> can use this ;)')


# Shrug because she can
@bot.command(pass_context=True, brief='Well what you think I do?')
async def shrug(ctx):
    await ctx.channel.send("¯\_(ツ)_/¯")


# Ping command
@bot.command(pass_context=True, brief='Pinging me to see if I\'m alive!')
async def ping(ctx):
    await ctx.send('Pong! {0}s'.format(round(bot.latency, 1)))


# Social command
@bot.command(pass_context=True, brief='My socials!')
async def socials(ctx):
    await ctx.channel.send("""Thanks for asking about my socials! Here they are ^-^
`🐤`　https://twitter.com/bubshoku
`👾`　https://www.twitch.tv/bubshoku""")


# Creator command
@bot.command(pass_context=True, Brief='Who made me?',
             description='Bub made me into a being and Roem made me come alive!')
async def creators(ctx):
    await ctx.channel.send("""Bub came up with my design and backstory, but Roem made me into a bot that interacts with
     the server! ^^""")


# Command to announce in the chat
@bot.command(pass_context=True, brief='Announce me streaming!',
             description='Use Bub announce <msg to announce>. Without the brackets The link is added at the end of the announcement')
async def announce(ctx, *, arg):
    modRole = discord.utils.get(ctx.guild.roles, name="the manager")
    notifyChannel = bot.get_channel(542233770871488522)
    if modRole in ctx.author.roles:
        await notifyChannel.send(arg)
    else:
        await ctx.send('You arent allowed to use this command! Only <@&630715988022788107> can use this ;)')


# Command for stream link
@bot.command(pass_context=True, brief='My stream link', description='The link to my stream ^^')
async def stream(ctx):
    await ctx.send('Thanks for asking about my stream! Here it is: https://twitch.tv/bubshoku')


# Command for timezone
@bot.command(pass_context=True, brief='Get timezones!')
async def currenttime(ctx):
    # UTC
    tmp1 = datetime.datetime.now()
    utcnow = datetime.time(hour=tmp1.hour, minute=tmp1.minute, second=tmp1.second)
    del tmp1
    utcfulltime = "{}:{}:{}".format(utcnow.hour, utcnow.minute, utcnow.second)

    # SMT
    tmp1 = datetime.timedelta(hours=4)
    smt = datetime.timezone(tmp1)
    tmp2 = datetime.datetime.now(smt)
    smtnow = datetime.time(hour=tmp2.hour, minute=tmp2.minute, second=tmp2.second)
    del tmp1
    del tmp2
    del smt
    smtfulltime = "{}:{}:{}".format(smtnow.hour, smtnow.minute, smtnow.second)

    # Print the timezones...
    await ctx.send("""```python
UTC: {} Where I live\nSMT: {}```""".format(utcfulltime, smtfulltime))
    # cleaning up
    del utcnow
    del smtnow


# Tell a joke
@bot.command(pass_context=True, brief="I will tell you a joke!")
async def joke(ctx):
    jokeList = ["Barista: How do you take your coffee? Me: Very, very seriously.",
                "Sleep is a weak substitute for coffee.",
                "What do you call a thieving alligator? A Crookodile",
                "What do you call a bee that can't make up its mind? A Maybe"
        , "Q: How do you stay warm in an empty room? A: Go stand in the corner—it’s always 90 degrees.",
                "Q. You find me in December, but not in any other month. What am I? A. The letter D!",
                "Did you hear about the monkeys who shared an Amazon account? They were Prime mates.",
                "How did the telephone propose to its girlfriend? He gave her a ring.",
                "You are like dandruff because I just cannot get you out of my head no matter how hard I try.",
                "When was the last time a Twitch streamer got laid? Aboout a fortnite ago."
        , "Why does Python live on land? Because its above C level",
                "I will tell you joke about czech postal service. But I'm not sure you will get it.",
                "First thing on my to-do list: Find a republic. Czech.", "What you call a fish with no eye? FSH!"]
    message = str(random.choice(jokeList))
    await ctx.send(message)


# Failsafe command to shut the bot off
@bot.command(pass_context=True, brief="Good Night!")
async def F41lS4fe(ctx):
    modRole = discord.utils.get(ctx.guild.roles, name="the manager")
    if modRole in ctx.author.roles:
        await ctx.send("Bub.exe is going offline! Testing is about to be done ^^")
        exit()


# -----------Music player-------------
# Music player work in progress
# @bot.command(pass_context=True, brief="Makes the bot join your channel")
# async def join(ctx):
#     if ctx.author.voice and ctx.author.voice.channel:
#         channel = ctx.message.author.voice.channel
#         voice = get(bot.voice_clients, guild=ctx.guild)
#         if voice and voice.is_connected():
#             await voice.move_to(channel)
#         else:
#             voice = await channel.connect()
#             await ctx.send(f'Connected to ``{channel}``')
#     else:
#         await ctx.send("You are not connected to voice!")
#
#
# @bot.command(pass_context=True, brief="This will play a song 'play [url]'")
# async def play(ctx, url: str):
#     song_there = os.path.isfile("song.mp3")
#     try:
#         if song_there:
#             os.remove("song.mp3")
#     except PermissionError:
#         await ctx.send("Wait for the current playing music end or use the 'stop' command")
#         return
#     await ctx.send("Getting everything ready, playing audio soon")
#     print("Someone wants to play music let me get that ready for them...")
#     voice = get(bot.voice_clients, guild=ctx.guild)
#     ydl_opts = {
#         'format': 'bestaudio/best',
#         'postprocessors': [{
#             'key': 'FFmpegExtractAudio',
#             'preferredcodec': 'mp3',
#             'preferredquality': '192',
#         }],
#     }
#     with youtube_dl.YoutubeDL(ydl_opts) as ydl:
#         ydl.download([url])
#     for file in os.listdir("./"):
#         if file.endswith(".mp3"):
#             os.rename(file, 'song.mp3')
#     voice.play(discord.FFmpegPCMAudio("song.mp3"))
#     voice.volume = 100
#     voice.is_playing()
#
#
# @bot.command(pass_context=True, brief="Makes the bot leave your channel")
# async def leave(ctx):
#     channel = ctx.message.author.voice.channel
#     voice = get(bot.voice_clients, guild=ctx.guild)
#     if voice and voice.is_connected():
#         await voice.disconnect()
#         await ctx.send(f"Left ``{channel}``")
#     else:
#         await ctx.send("Don't think I am in a voice channel")
#
#
# @bot.command(pass_context=True, brief="Resumes the song that was playing")
# async def resume(ctx):
#     voice = get(bot.voice_clients, guild=ctx.guild)
#
#     if not voice.is_playing():
#         voice.resume()
#         await ctx.send(':play_pause: Song is resuming')
#
#
# @bot.command(pass_context=True, brief="Stops the song that was playing")
# async def stop(ctx):
#     voice = get(bot.voice_clients, guild=ctx.guild)
#
#     if voice.is_playing():
#         voice.stop()
#         await ctx.send(':stop_button: Stopping...')
#
#
# @bot.command(pass_context=True, brief="Pauses the song that is playing")
# async def pause(ctx):
#     voice = get(bot.voice_clients, guild=ctx.guild)
#
#     if voice.is_playing():
#         voice.pause()
#         await ctx.send(':pause_button: Song has been paused')


bot.run(token)
