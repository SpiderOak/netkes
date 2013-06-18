Remote Preferences
==================

The SpiderOak: Blue™ client supports management of client preferences through central configuration per client machine.  Currently only Windows registry settings are available, however Mac and Linux settings are coming soon.

When settings are configured centrally, the SpiderOak: Blue™ client will use them over locally-configured settings, as a method to enforce policy.

Windows Configuration
*********************

Windows central management is accomplished via the registry.  This enables administrators to push registry settings via Group Policy Objects administered at the domain level.

Both ``HKEY_CURRENT_USER`` and ``HKEY_LOCAL_MACHINE`` trees are supported, with ``HKEY_LOCAL_MACHINE`` taking priority.  The location in the registry for the preferences is ``\SOFTWARE\SpiderOak\SpiderOak\Preferences``.

.. warning::
    
    Note that if you are manually editing preferences in ``HKEY_LOCAL_MACHINE`` with ``regedit`` on 64-bit Windows, you need to place these in a 32-bit compatability key, as: ``HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\SpiderOak\SpiderOak\Preferences``

Supported Registry Preference Value Types
+++++++++++++++++++++++++++++++++++++++++

The following types are used in SpiderOak registry settings:

* Boolean:

  * String (``REG_SZ``) of ``True`` or ``False``
  * ``REG_DWORD`` or ``REG_QWORD`` with values 0 for ``False``, 1 for ``True``.

* String:

  * String (``REG_SZ``)

* Integer:

  * String (``REG_SZ``) representation of the integer (example: ``"12345"``)
  * ``REG_DWORD`` or ``REG_QWORD`` of the value.

Supported Preferences
+++++++++++++++++++++

Interface
---------

* ShowCloseOrMinimizeDialogOnClose : Boolean
* MinimizeToTrayOnClose : Boolean
* LaunchMinimizedAtStartup : Boolean
* ShowSplashScreenAtStartup : Boolean
* UseAlternativeTrayIconStyle : Boolean
* DisableSpaceCalculations : Boolean
* ShowHotkeyEnabled : Boolean
* ShowHotkeyModifier : String

  * Options: ``Alt``, ``Ctrl``, ``Alt + Ctrl``, ``Alt + Shift``, ``Ctrl + Shift``

* ShowHotkeySymbol : String

  * A single capitalized letter string value, e.g. "S".
  * Spacebar represented as ``SPACE``.

Backup
------

* DontArchiveFilesLargerThanEnabled : Boolean
* DontArchiveFilesLargerThanSize : Integer
* DontArchiveFilesOlderThanEnabled :  Boolean
* DontArchiveFilesOlderThanSeconds : Integer

  * Value is in seconds.

* !Wildcards : String
* FolderWildcards : String
* EnablePreviews : Boolean

Schedule
--------

For the values ending in "ScanInterval", the following options are available: ``Automatic``, ``5 Minutes``, ``15 Minutes``, ``30 Minutes``, ``1 Hour``, ``2 Hours``, ``4 Hours``, ``8 Hours``, ``12 Hours``, ``24 Hours``, and ``48 Hours``.

For the values ending in "ScheduleDay", the following options are available: ``Everyday``, ``Monday``, ``Tuesday``, ``Wednesday``, ``Thursday``, ``Friday``, ``Saturday``, ``Sunday``, ``Weekdays``, and ``Weekends``.

For the values ending in "ScheduleHour", values are strings of the integers "1" through "12".

For the AMPM values, the value is either ``AM`` or ``PM``.

* FullScheduleEnable : Boolean
* FullScanInterval : String
* FullScheduleDay : String
* FullScheduleHour : String
* !FullScheduleAMPM : String
* SyncScheduleEnable : Boolean
* SyncScanInterval : String
* SyncScheduleDay : String
* SyncScheduleHour : String 
* !SyncScheduleAMPM : String
* ShareScheduleEnable : Boolean
* ShareScanInterval : String
* ShareScheduleDay : String
* ShareScheduleHour : String
* !ShareScheduleAMPM : String
* EnableAutomaticScan : Boolean

Copy
----

* SecondaryCopyEnabled : Boolean
* SecondaryCopyLocationType : String

  * Options: ``Local Folder``, ``FTP Server``, ``SFTP Server``

* SecondaryCopyLocation : String
* SecondaryCopyHostname : String
* SecondaryCopyPort : String
* SecondaryCopyUsername : String
* SecondaryCopyPassword : String

Proxy
-----

* HttpProxyEnabled : Boolean
* HttpProxyHost : String
* HttpProxyPort : String
* HttpProxyUsername : String
* LimitBandwidthEnabled : Boolean
* LimitUploadBucket : String

General
-------

* DownloadsLocation : String



