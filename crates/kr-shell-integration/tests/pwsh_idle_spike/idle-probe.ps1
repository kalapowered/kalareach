# T-WIN-PWSH-LEGS-1 spike: what a parked PSReadLine reader does at its idle tick, with nothing typed.
#
# Dot-sourced by the first command of a pwsh that runs in a pseudo-console, so the prompt function
# and the subscribers below belong to the session that goes on to read lines. The test connects to
# the named pipe this creates, sends requests, and reads the answers the idle subscriber writes.

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Pipe,
    [Parameter(Mandatory)][string]$Report,
    # Queue a key of the probe's own at the start of each read, as the module does off Windows.
    [switch]$StartStep
)

Add-Type -TypeDefinition @'
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Text;
using System.Threading;

public sealed class SpikeRequest
{
    public string Id;
    public string Kind;
    public string Payload;
    public long Arrived;
    public int ArrivedOn;
}

public static class SpikeMailbox
{
    static readonly ConcurrentQueue<SpikeRequest> Queue = new ConcurrentQueue<SpikeRequest>();
    static readonly object Gate = new object();
    static NamedPipeServerStream pipe;
    static StreamWriter writer;

    public static string ReportPath;
    public static volatile int ReaderThread;
    public static int PersonTicks;
    public static int ServiceCalls;
    public static long PromptAt;
    public static int Prompts;

    public static void Log(string line)
    {
        lock (Gate) { File.AppendAllText(ReportPath, line + "\n"); }
    }

    public static void Start(string name)
    {
        // Asynchronous, because one thread waits in a read while another writes an answer.
        pipe = new NamedPipeServerStream(name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
        var thread = new Thread(ReadRequests) { IsBackground = true, Name = "spike-pipe-reader" };
        thread.Start();
    }

    static void ReadRequests()
    {
        try
        {
            pipe.WaitForConnection();
            var utf8 = new UTF8Encoding(false);
            writer = new StreamWriter(pipe, utf8) { AutoFlush = true, NewLine = "\n" };
            var reader = new StreamReader(pipe, utf8);
            string line;
            while ((line = reader.ReadLine()) != null)
            {
                var parts = line.Split(new[] { '|' }, 3);
                Queue.Enqueue(new SpikeRequest
                {
                    Id = parts[0],
                    Kind = parts.Length > 1 ? parts[1] : "",
                    Payload = parts.Length > 2 ? parts[2] : "",
                    Arrived = Stopwatch.GetTimestamp(),
                    ArrivedOn = Thread.CurrentThread.ManagedThreadId,
                });
            }
            Log("pipe closed by the test");
        }
        catch (Exception error)
        {
            Log("pipe reader failed: " + error);
        }
    }

    // Answers what is waiting, on the calling thread, and returns the lines to run.
    public static string[] Service(string via)
    {
        long serviced = Stopwatch.GetTimestamp();
        int thread = Thread.CurrentThread.ManagedThreadId;
        bool pool = Thread.CurrentThread.IsThreadPoolThread;
        ServiceCalls++;
        var launches = new List<string>();
        SpikeRequest request;
        while (Queue.TryDequeue(out request))
        {
            if (request.Kind == "L") { launches.Add(request.Payload); }
            long waitedUs = (serviced - request.Arrived) * 1000000L / Stopwatch.Frequency;
            long sincePromptUs = (serviced - PromptAt) * 1000000L / Stopwatch.Frequency;
            var answer = "A|" + request.Id + "|" + request.Kind + "|" + via
                + "|reader=" + ReaderThread + "|action=" + thread + "|pool=" + pool
                + "|waited_us=" + waitedUs + "|since_prompt_us=" + sincePromptUs
                + "|person_ticks=" + PersonTicks + "|calls=" + ServiceCalls + "|prompts=" + Prompts;
            lock (Gate) { writer.WriteLine(answer); }
        }
        return launches.ToArray();
    }

    public static void StartStep()
    {
        long now = Stopwatch.GetTimestamp();
        long sincePromptUs = (now - PromptAt) * 1000000L / Stopwatch.Frequency;
        Log("start_step prompt=" + Prompts + " thread=" + Thread.CurrentThread.ManagedThreadId
            + " reader=" + ReaderThread + " since_prompt_us=" + sincePromptUs);
    }
}
'@

[SpikeMailbox]::ReportPath = $Report
$global:SpikeStartStep = [bool]$StartStep
$global:SpikeStartChord = 'Ctrl+Alt+F24'

$readLine = Get-Module PSReadLine
[SpikeMailbox]::Log(("host pwsh={0} psreadline={1} edit_mode={2} start_step={3} os={4}" -f
        $PSVersionTable.PSVersion, $readLine.Version, (Get-PSReadLineOption).EditMode, $StartStep,
        [System.Environment]::OSVersion.VersionString))

# What the person has subscribed: it has to keep running beside the probe's own subscriber.
$null = Register-EngineEvent -SourceIdentifier PowerShell.OnIdle -SupportEvent -Action {
    [SpikeMailbox]::PersonTicks++
}

# The probe's subscriber: reads the mailbox on whichever thread the editor runs it on, and runs a
# launched line the way the editor documents for an idle handler, by replacing the buffer and
# accepting it.
$null = Register-EngineEvent -SourceIdentifier PowerShell.OnIdle -SupportEvent -Action {
    $launches = [SpikeMailbox]::Service('idle')
    foreach ($line in $launches) {
        try {
            [Microsoft.PowerShell.PSConsoleReadLine]::RevertLine()
            [Microsoft.PowerShell.PSConsoleReadLine]::Insert($line)
            [Microsoft.PowerShell.PSConsoleReadLine]::AcceptLine()
            [SpikeMailbox]::Log('accept returned normally')
        } catch {
            [SpikeMailbox]::Log(('accept threw {0}: {1}' -f $_.Exception.GetType().FullName, $_.Exception.Message))
            throw
        }
    }
}

function global:Add-SpikeStartKey {
    try {
        $type = [Microsoft.PowerShell.PSConsoleReadLine]
        $singleton = $type.GetField('_singleton', 'NonPublic,Static').GetValue($null)
        $queue = $type.GetField('_queuedKeys', 'NonPublic,Instance').GetValue($singleton)
        if ($queue.Count -gt 0) { [SpikeMailbox]::Log('start key not queued: the queue holds keys'); return }
        $assembly = $type.Assembly
        $chords = $assembly.GetType('Microsoft.PowerShell.ConsoleKeyChordConverter').GetMethod(
            'Convert', [type[]]@([string])).Invoke($null, @($global:SpikeStartChord))
        $key = $assembly.GetType('Microsoft.PowerShell.PSKeyInfo').GetMethod(
            'FromConsoleKeyInfo', [type[]]@([System.ConsoleKeyInfo])).Invoke($null, @(@($chords)[0]))
        $queue.Enqueue($key)
    } catch {
        [SpikeMailbox]::Log("start key not queued: $($_.Exception.Message)")
    }
}

if ($StartStep) {
    Set-PSReadLineKeyHandler -Chord $global:SpikeStartChord -BriefDescription 'SpikeStart' -ScriptBlock {
        param($key, $arg)
        [SpikeMailbox]::StartStep()
        $null = [SpikeMailbox]::Service('start')
    }
}

function global:prompt {
    [SpikeMailbox]::ReaderThread = [System.Threading.Thread]::CurrentThread.ManagedThreadId
    [SpikeMailbox]::PromptAt = [System.Diagnostics.Stopwatch]::GetTimestamp()
    [SpikeMailbox]::Prompts++
    [SpikeMailbox]::Log(('prompt {0} thread={1}' -f [SpikeMailbox]::Prompts, [SpikeMailbox]::ReaderThread))
    if ($global:SpikeStartStep) { Add-SpikeStartKey }
    'PS> '
}

[SpikeMailbox]::Start($Pipe)
[SpikeMailbox]::Log('probe loaded')
