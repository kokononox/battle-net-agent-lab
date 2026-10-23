# File-handle sharing, not file existence or thread-owned Mutex state, controls capture.
# An abandoned on-disk file does not block a new attempt after the handle is closed.
function Acquire-WLabCaptureLock($root){
[void][IO.Directory]::CreateDirectory($root)
return [IO.File]::Open((Join-Path $root 'capture.lock'),[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
}
function Release-WLabCaptureLock($handle){
if($null -ne $handle){$handle.Dispose()}
}
