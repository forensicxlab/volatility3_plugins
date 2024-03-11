# About
This repository contains volatility3 plugins for the <a href="https://github.com/volatilityfoundation/volatility3/">volatility3</a> framework.


# Windows plugins

## Prefetch

The plugin is scanning, extracting and parsing Windows Prefetch files from Windows XP to Windows 11.
<br>
More information here : <a href="https://www.forensicxlab.com/posts/prefetch/">https://www.forensicxlab.com/posts/prefetch/</a>

## AnyDesk

The plugin is scanning, extracting and parsing Windows AnyDesk trace files.
<br>
More information here : <a href="https://www.forensicxlab.com/posts/anydesk/">https://www.forensicxlab.com/posts/anydesk/</a>

## KeePass
The plugin is scanning the keepass process for potential password recovery following CVE-2023-32784
<br>
More information here : <a href="https://www.forensicxlab.com/posts/keepass/">https://www.forensicxlab.com/posts/keepass/</a>

## Hibernation

The layer & plugins aims to add support of the conversion of the hiberfile.sys to a raw memory image to the volatility3 framework. 
Pull request: https://github.com/volatilityfoundation/volatility3/pull/1036
More information here : <a href="https://www.forensicxlab.com/posts/hibernation/">https://www.forensicxlab.com/posts/hibernation/</a>

## Import Address Table (IAT)
The plugin aims to carve the Import Address Table from a PE, it is giving information about the functions imported and therefore the cabapilities of a potential malicious process.
Pull request: https://github.com/volatilityfoundation/volatility3/pull/1063
More information here : <a href="https://www.forensicxlab.com/posts/voliat/">https://www.forensicxlab.com/posts/voliat/</a>

## Alternate Data Streams (ADS)

The plugin aims to carve the ADS from the MFT.
Pull request: https://github.com/volatilityfoundation/volatility3/pull/1063
More information here : <a href="https://www.forensicxlab.com/posts/volads/">https://www.forensicxlab.com/posts/volads/</a>


# Linux plugins

## Inodes

The plugin is a pushed version of the lsof plugin, extracting inode metadata from each files.
<br>
More information here : <a href="https://www.forensicxlab.com/posts/inodes/">https://www.forensicxlab.com/posts/inodes/</a>
Pull request : TBD.


# Translation layers
## Remote analysis on cloud object-storage. 
More information here : <a href="https://www.forensicxlab.com/posts/vols3/">https://www.forensicxlab.com/posts/vols3/</a>
Pull request: https://github.com/volatilityfoundation/volatility3/pull/1044
