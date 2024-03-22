# JavaChat-Applet

A simple Javacard Applet implementation for [JavaChatNT](https://github.com/guigitignore/JavaChatNT.git) project

## Build

You need `JavaCardSDK-stud` kit to build this applet.
First, clone the project inside `src` folder.
Then , go to `scripts.win32` folder and edit the first line of `setenv.bat` to select the project:
`set PROJECT=JavaChatApplet`

Finally you can run the following scripts in `scripts.win32`:

- `1_makeApplet.bat`
- `card-deleteApplet.bat`
- `card-installApplet.bat`
