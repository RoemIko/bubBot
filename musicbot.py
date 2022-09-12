# -----------Music player-------------
# Music player work in progress
@bot.command(pass_context=True, brief="Makes the bot join your channel")
async def join(ctx):
    if ctx.author.voice and ctx.author.voice.channel:
        channel = ctx.message.author.voice.channel
        voice = get(bot.voice_clients, guild=ctx.guild)
        if voice and voice.is_connected():
            await voice.move_to(channel)
        else:
            voice = await channel.connect()
            await ctx.send(f'Connected to ``{channel}``')
    else:
        await ctx.send("You are not connected to voice!")


@bot.command(pass_context=True, brief="This will play a song 'play [url]'")
async def play(ctx, url: str):
    song_there = os.path.isfile("song.mp3")
    try:
        if song_there:
            os.remove("song.mp3")
    except PermissionError:
        await ctx.send("Wait for the current playing music end or use the 'stop' command")
        return
    await ctx.send("Getting everything ready, playing audio soon")
    print("Someone wants to play music let me get that ready for them...")
    voice = get(bot.voice_clients, guild=ctx.guild)
    ydl_opts = {
        'format': 'bestaudio/best',
        'postprocessors': [{
            'key': 'FFmpegExtractAudio',
            'preferredcodec': 'mp3',
            'preferredquality': '192',
        }],
    }
    with youtube_dl.YoutubeDL(ydl_opts) as ydl:
        ydl.download([url])
    for file in os.listdir("./"):
        if file.endswith(".mp3"):
            os.rename(file, 'song.mp3')
    voice.play(discord.FFmpegPCMAudio("song.mp3"))
    voice.volume = 100
    voice.is_playing()


@bot.command(pass_context=True, brief="Makes the bot leave your channel")
async def leave(ctx):
    channel = ctx.message.author.voice.channel
    voice = get(bot.voice_clients, guild=ctx.guild)
    if voice and voice.is_connected():
        await voice.disconnect()
        await ctx.send(f"Left ``{channel}``")
    else:
        await ctx.send("Don't think I am in a voice channel")


@bot.command(pass_context=True, brief="Resumes the song that was playing")
async def resume(ctx):
    voice = get(bot.voice_clients, guild=ctx.guild)

    if not voice.is_playing():
        voice.resume()
        await ctx.send(':play_pause: Song is resuming')


@bot.command(pass_context=True, brief="Stops the song that was playing")
async def stop(ctx):
    voice = get(bot.voice_clients, guild=ctx.guild)

    if voice.is_playing():
        voice.stop()
        await ctx.send(':stop_button: Stopping...')


@bot.command(pass_context=True, brief="Pauses the song that is playing")
async def pause(ctx):
    voice = get(bot.voice_clients, guild=ctx.guild)

    if voice.is_playing():
        voice.pause()
        await ctx.send(':pause_button: Song has been paused')