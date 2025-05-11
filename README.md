# CenLdr

Not Thing && Not Thing New , Just A Simple Shellcode Loadee :D 

## Disclaimer👀👀

This project is only used for education and learning purposes, and any illegal activities have nothing to do with me :D

本项目仅用作教育用途，任何非法利用与本作者无关

<img src=".\Img\lol.png" alt="lol" style="zoom:150%;" />  



## Features && Todo ?

- UnHook In A More Elegant Way ？ Or Just Lets Say Syscall :>

  <img src=".\Img\BeforeUnHook.png" alt="BeforeUnHook" style="zoom: 67%;" /> 

  It Will Still Work In Some EDR Environment ：）

   <img src=".\Img\UnHook.png" alt="UnHook" style="zoom:67%;" />

  

- Spoof  Call ? **Maybe More "Evasive" Techniques Should Be Used In Your UDRL **

- CRC32 API Hash (When Calling GetProcAddressByHash)

- GetMoudleHandle From Stack (**Kernel32!BaseThreadInitThunk+0x14 && Ntdll!RtlUserThreadStart+0x21**)

- ModuleStomping(***Now I Will Never Have "Unbackend Memory"***) -> [Goes With BRC4 PebPatch](https://bruteratel.com/release/2023/03/19/Release-Nightmare/)

    <img src=".\Img\PebPatch.png" alt="PebPatch" style="zoom:67%;" />

- Thread Start Address Spoof (When Combine With udrl's Spoof Call, It Will Look Like This) :>

<img src=".\Img\ThreadStack.png" alt="ThreadStack" style="zoom: 67%;" /> 

- Anti SandBox && Debugger (Whatever, I Have Never Get A Beacon From My VMMachine :D )

  ![VMMachine](.\Img\VMMachine.png) 

- PreLoad(This Will Be Quite Effective When Comes With Some EDR)

  <img src=".\Img\EDRTest.png" alt="EDRTest" style="zoom:67%;" /> 



