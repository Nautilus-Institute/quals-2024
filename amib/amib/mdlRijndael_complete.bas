Attribute VB_Name = "mdlRijndael"
' Ref: https://gist.github.com/ryno1234/2fc83faff281babea7f8

Private m_lOnBits(30) As Long
Private m_l2Power(30) As Long
Private m_bytOnBits(7) As Byte
Private m_byt2Power(7) As Byte
Private m_InCo(3) As Byte
Private m_fbsub(255) As Long
Private m_rbsub(255) As Long
Private m_ptab(255) As Byte
Private m_ltab(255) As Byte
Private m_ftable(255) As Long
Private m_rtable(255) As Long
Private m_rco(29) As Long
Private m_Nk
Private m_Nb
Private m_Nr
Private m_fi(23)
Private m_ri(23)
Private m_fkey(119) As Long
Private m_rkey(119) As Long

Public Sub RijndaelInitialize()
    m_InCo(0) = &HB
    m_InCo(1) = &HD
    m_InCo(2) = &H9
    m_InCo(3) = &HE
    
    m_bytOnBits(0) = 1
    m_bytOnBits(1) = 3
    m_bytOnBits(2) = 7
    m_bytOnBits(3) = 15
    m_bytOnBits(4) = 31
    m_bytOnBits(5) = 63
    m_bytOnBits(6) = 127
    m_bytOnBits(7) = 255
        
    m_byt2Power(0) = 1
    m_byt2Power(1) = 2
    m_byt2Power(2) = 4
    m_byt2Power(3) = 8
    m_byt2Power(4) = 16
    m_byt2Power(5) = 32
    m_byt2Power(6) = 64
    m_byt2Power(7) = 128
        
    m_lOnBits(0) = 1
    m_lOnBits(1) = 3
    m_lOnBits(2) = 7
    m_lOnBits(3) = 15
    m_lOnBits(4) = 31
    m_lOnBits(5) = 63
    m_lOnBits(6) = 127
    m_lOnBits(7) = 255
    m_lOnBits(8) = 511
    m_lOnBits(9) = 1023
    m_lOnBits(10) = 2047
    m_lOnBits(11) = 4095
    m_lOnBits(12) = 8191
    m_lOnBits(13) = 16383
    m_lOnBits(14) = 32767
    m_lOnBits(15) = 65535
    m_lOnBits(16) = 131071
    m_lOnBits(17) = 262143
    m_lOnBits(18) = 524287
    m_lOnBits(19) = 1048575
    m_lOnBits(20) = 2097151
    m_lOnBits(21) = 4194303
    m_lOnBits(22) = 8388607
    m_lOnBits(23) = 16777215
    m_lOnBits(24) = 33554431
    m_lOnBits(25) = 67108863
    m_lOnBits(26) = 134217727
    m_lOnBits(27) = 268435455
    m_lOnBits(28) = 536870911
    m_lOnBits(29) = 1073741823
    m_lOnBits(30) = 2147483647
        
    m_l2Power(0) = 1
    m_l2Power(1) = 2
    m_l2Power(2) = 4
    m_l2Power(3) = 8
    m_l2Power(4) = 16
    m_l2Power(5) = 32
    m_l2Power(6) = 64
    m_l2Power(7) = 128
    m_l2Power(8) = 256
    m_l2Power(9) = 512
    m_l2Power(10) = 1024
    m_l2Power(11) = 2048
    m_l2Power(12) = 4096
    m_l2Power(13) = 8192
    m_l2Power(14) = 16384
    m_l2Power(15) = 32768
    m_l2Power(16) = 65536
    m_l2Power(17) = 131072
    m_l2Power(18) = 262144
    m_l2Power(19) = 524288
    m_l2Power(20) = 1048576
    m_l2Power(21) = 2097152
    m_l2Power(22) = 4194304
    m_l2Power(23) = 8388608
    m_l2Power(24) = 16777216
    m_l2Power(25) = 33554432
    m_l2Power(26) = 67108864
    m_l2Power(27) = 134217728
    m_l2Power(28) = 268435456
    m_l2Power(29) = 536870912
    m_l2Power(30) = 1073741824
End Sub

Private Function LShift(lValue As Long, iShiftBits As Long) As Long
    If iShiftBits = 0 Then
        LShift = lValue
        Exit Function
    ElseIf iShiftBits = 31 Then
        If lValue And 1 Then
            LShift = &H80000000
        Else
            LShift = 0
        End If
        Exit Function
    ElseIf iShiftBits < 0 Or iShiftBits > 31 Then
        Err.Raise 6
    End If
    
    If (lValue And m_l2Power(31 - iShiftBits)) Then
        LShift = ((lValue And m_lOnBits(31 - (iShiftBits + 1))) * m_l2Power(iShiftBits)) Or &H80000000
    Else
        LShift = ((lValue And m_lOnBits(31 - iShiftBits)) * m_l2Power(iShiftBits))
    End If
End Function

Private Function RShift(lValue As Long, iShiftBits As Long)
    If iShiftBits = 0 Then
        RShift = lValue
        Exit Function
    ElseIf iShiftBits = 31 Then
        If lValue And &H80000000 Then
            RShift = 1
        Else
            RShift = 0
        End If
        Exit Function
    ElseIf iShiftBits < 0 Or iShiftBits > 31 Then
        Err.Raise 6
    End If
    
    RShift = (lValue And &H7FFFFFFE) \ m_l2Power(iShiftBits)
    
    If (lValue And &H80000000) Then
        RShift = (RShift Or (&H40000000 \ m_l2Power(iShiftBits - 1)))
    End If
End Function

Private Function LShiftByte(bytValue As Byte, bytShiftBits As Long)
    If bytShiftBits = 0 Then
        LShiftByte = bytValue
        Exit Function
    ElseIf bytShiftBits = 7 Then
        If bytValue And 1 Then
            LShiftByte = &H80
        Else
            LShiftByte = 0
        End If
        Exit Function
    ElseIf bytShiftBits < 0 Or bytShiftBits > 7 Then
        Err.Raise 6
    End If
    
    LShiftByte = ((bytValue And m_bytOnBits(7 - bytShiftBits)) * m_byt2Power(bytShiftBits))
End Function

Private Function RShiftByte(bytValue As Byte, bytShiftBits As Long)
    If bytShiftBits = 0 Then
        RShiftByte = bytValue
        Exit Function
    ElseIf bytShiftBits = 7 Then
        If bytValue And &H80 Then
            RShiftByte = 1
        Else
            RShiftByte = 0
        End If
        Exit Function
    ElseIf bytShiftBits < 0 Or bytShiftBits > 7 Then
        Err.Raise 6
    End If
    
    RShiftByte = bytValue \ m_byt2Power(bytShiftBits)
End Function

Private Function RotateLeft(lValue As Long, iShiftBits As Long)
    RotateLeft = LShift(lValue, iShiftBits) Or RShift(lValue, (32 - iShiftBits))
End Function

Private Function RotateLeftByte(bytValue As Byte, bytShiftBits As Long)
    RotateLeftByte = LShiftByte(bytValue, bytShiftBits) Or RShiftByte(bytValue, (8 - bytShiftBits))
End Function

Private Function Pack(b() As Byte)
    Dim lCount As Long, lTemp As Long
    
    For lCount = 0 To 3
        lTemp = b(lCount)
        Pack = Pack Or LShift(lTemp, (lCount * 8))
    Next
End Function

Private Function PackFrom(b() As Byte, k As Long)
    Dim lCount As Long, lTemp As Long
    
    For lCount = 3 To 0 Step -1
        lTemp = b(lCount + k)
        PackFrom = PackFrom Or LShift(lTemp, (lCount * 8))
    Next
End Function

Private Function PackFromBE(b() As Byte, k As Long)
    Dim lCount As Long, lTemp As Long
    
    For lCount = 3 To 0 Step -1
        lTemp = b(lCount + k)
        PackFromBE = PackFromBE Or LShift(lTemp, ((3 - lCount) * 8))
    Next
End Function

Private Sub Unpack(a As Long, b() As Byte)
    b(0) = a And m_lOnBits(7)
    b(1) = RShift(a, 8) And m_lOnBits(7)
    b(2) = RShift(a, 16) And m_lOnBits(7)
    b(3) = RShift(a, 24) And m_lOnBits(7)
End Sub

Private Sub UnpackFrom(a As Long, b() As Byte, k As Long)
    b(0 + k) = a And m_lOnBits(7)
    b(1 + k) = RShift(a, 8) And m_lOnBits(7)
    b(2 + k) = RShift(a, 16) And m_lOnBits(7)
    b(3 + k) = RShift(a, 24) And m_lOnBits(7)
End Sub

Private Function xtime(a As Byte)
    Dim b As Byte
    
    If (a And &H80) Then
        b = &H1B
    Else
        b = 0
    End If
    
    xtime = LShiftByte(a, 1)
    xtime = xtime Xor b
End Function

Private Function bmul(x As Byte, y As Byte)
    If x <> 0 And y <> 0 Then
        bmul = m_ptab((CLng(m_ltab(x)) + CLng(m_ltab(y))) Mod 255)
    Else
        bmul = 0
    End If
End Function

Private Function SubByte(a As Long)
    Dim b(3) As Byte
    
    Unpack a, b
    b(0) = m_fbsub(b(0))
    b(1) = m_fbsub(b(1))
    b(2) = m_fbsub(b(2))
    b(3) = m_fbsub(b(3))
    
    SubByte = Pack(b)
End Function

Private Function product(x As Long, y As Long)
    Dim xb(3) As Byte, yb(3) As Byte
    
    Unpack x, xb
    Unpack y, yb
    product = bmul(xb(0), yb(0)) Xor bmul(xb(1), yb(1)) Xor bmul(xb(2), yb(2)) Xor bmul(xb(3), yb(3))
End Function

Private Function InvMixCol(x As Long)
    Dim y As Long, m As Long
    Dim b(3) As Byte
    
    m = Pack(m_InCo)
    b(3) = product(m, x)
    m = RotateLeft(m, 24)
    b(2) = product(m, x)
    m = RotateLeft(m, 24)
    b(1) = product(m, x)
    m = RotateLeft(m, 24)
    b(0) = product(m, x)
    y = Pack(b)
    
    InvMixCol = y
End Function

Private Function ByteSub(x As Byte)
    Dim y As Byte, z As Byte
    
    z = x
    y = m_ptab(255 - m_ltab(z))
    z = y
    z = RotateLeftByte(z, 1)
    y = y Xor z
    z = RotateLeftByte(z, 1)
    y = y Xor z
    z = RotateLeftByte(z, 1)
    y = y Xor z
    z = RotateLeftByte(z, 1)
    y = y Xor z
    y = y Xor &H63
    
    ByteSub = y
End Function

Public Sub gentables()
    Dim i As Long, y As Byte
    Dim b(3) As Byte
    Dim ib As Byte
    
    m_ltab(0) = 0
    m_ptab(0) = 1
    m_ltab(1) = 0
    m_ptab(1) = 3
    m_ltab(3) = 1
    
    For i = 2 To 255
        m_ptab(i) = m_ptab(i - 1) Xor xtime(m_ptab(i - 1))
        m_ltab(m_ptab(i)) = i
    Next i
    
    m_fbsub(0) = &H63
    m_rbsub(&H63) = 0
    
    For i = 1 To 255
        ib = i
        y = ByteSub(ib)
        m_fbsub(i) = y
        m_rbsub(y) = i
    Next
    
    y = 1
    For i = 0 To 29
        m_rco(i) = y
        y = xtime(y)
    Next
    
    For i = 0 To 255
        y = m_fbsub(i)
        b(3) = y Xor xtime(y)
        b(2) = y
        b(1) = y
        b(0) = xtime(y)
        m_ftable(i) = Pack(b)
        
        y = m_rbsub(i)
        b(3) = bmul(m_InCo(0), y)
        b(2) = bmul(m_InCo(1), y)
        b(1) = bmul(m_InCo(2), y)
        b(0) = bmul(m_InCo(3), y)
        m_rtable(i) = Pack(b)
    Next
End Sub

Public Sub gkey(nb, nk, key() As Byte)
    Dim i As Long, j As Long, k As Long
    Dim m As Long
    Dim n As Long
    Dim C1
    Dim C2
    Dim C3
    Dim CipherKey(7)
    
    m_Nb = nb
    m_Nk = nk
    
    If m_Nb >= m_Nk Then
        m_Nr = 6 + m_Nb
    Else
        m_Nr = 6 + m_Nk
    End If
    
    C1 = 1
    If m_Nb < 8 Then
        C2 = 2
        C3 = 3
    Else
        C2 = 3
        C3 = 4
    End If
    
    For j = 0 To nb - 1
        m = j * 3
        
        m_fi(m) = (j + C1) Mod nb
        m_fi(m + 1) = (j + C2) Mod nb
        m_fi(m + 2) = (j + C3) Mod nb
        m_ri(m) = (nb + j - C1) Mod nb
        m_ri(m + 1) = (nb + j - C2) Mod nb
        m_ri(m + 2) = (nb + j - C3) Mod nb
    Next
    
    n = m_Nb * (m_Nr + 1)
    
    For i = 0 To m_Nk - 1
        j = i * 4
        CipherKey(i) = PackFromBE(key, j)
    Next
    
    For i = 0 To m_Nk - 1
        m_fkey(i) = CipherKey(i)
    Next
    
    j = m_Nk
    k = 0
    Do While j < n
        m_fkey(j) = m_fkey(j - m_Nk) Xor _
            SubByte(RotateLeft(m_fkey(j - 1), 24)) Xor m_rco(k)
        If m_Nk <= 6 Then
            i = 1
            Do While i < m_Nk And (i + j) < n
                m_fkey(i + j) = m_fkey(i + j - m_Nk) Xor _
                    m_fkey(i + j - 1)
                i = i + 1
            Loop
        Else
            i = 1
            Do While i < 4 And (i + j) < n
                m_fkey(i + j) = m_fkey(i + j - m_Nk) Xor _
                    m_fkey(i + j - 1)
                i = i + 1
            Loop
            If j + 4 < n Then
                m_fkey(j + 4) = m_fkey(j + 4 - m_Nk) Xor _
                    SubByte(m_fkey(j + 3))
            End If
            i = 5
            Do While i < m_Nk And (i + j) < n
                m_fkey(i + j) = m_fkey(i + j - m_Nk) Xor _
                    m_fkey(i + j - 1)
                i = i + 1
            Loop
        End If
        
        j = j + m_Nk
        k = k + 1
    Loop
    
    For j = 0 To m_Nb - 1
        m_rkey(j + n - nb) = m_fkey(j)
    Next
    
    i = m_Nb
    Do While i < n - m_Nb
        k = n - m_Nb - i
        For j = 0 To m_Nb - 1
            m_rkey(k + j) = InvMixCol(m_fkey(i + j))
        Next
        i = i + m_Nb
    Loop
    
    j = n - m_Nb
    Do While j < n
        m_rkey(j - n + m_Nb) = m_fkey(j)
        j = j + 1
    Loop
    
    Dim s As String
    For i = 0 To UBound(m_fkey)
        s = s & ", " & Str(m_fkey(i))
    Next i
    Debug.Print s
End Sub

Public Sub encrypt(buff() As Byte)
    Dim i As Long, j As Long, k As Long, m As Long
    Dim a(7) As Long
    Dim b(7) As Long
    Dim x() As Long
    Dim y() As Long
    Dim t
    
    For i = 0 To m_Nb - 1
        j = i * 4
        a(i) = PackFromBE(buff, j) Xor m_fkey(i)
    Next
    
    k = m_Nb
    x = a
    y = b
    
    For i = 1 To m_Nr - 1
        For j = 0 To m_Nb - 1
            m = j * 3
            y(j) = m_fkey(k) Xor m_ftable(x(j) And m_lOnBits(7)) Xor _
                RotateLeft(m_ftable(RShift(x(m_fi(m)), 8) And m_lOnBits(7)), 8) Xor _
                RotateLeft(m_ftable(RShift(x(m_fi(m + 1)), 16) And m_lOnBits(7)), 16) Xor _
                RotateLeft(m_ftable(RShift(x(m_fi(m + 2)), 24) And m_lOnBits(7)), 24)
            Debug.Print y(j)
            k = k + 1
        Next
        t = x
        x = y
        y = t
    Next
    
    For j = 0 To m_Nb - 1
        m = j * 3
        y(j) = m_fkey(k) Xor m_fbsub(x(j) And m_lOnBits(7)) Xor _
            RotateLeft(m_fbsub(RShift(x(m_fi(m)), 8) And m_lOnBits(7)), 8) Xor _
            RotateLeft(m_fbsub(RShift(x(m_fi(m + 1)), 16) And m_lOnBits(7)), 16) Xor _
            RotateLeft(m_fbsub(RShift(x(m_fi(m + 2)), 24) And m_lOnBits(7)), 24)
        k = k + 1
    Next
    
    For i = 0 To m_Nb - 1
        j = i * 4
        UnpackFrom y(i), buff, j
        x(i) = 0
        y(i) = 0
    Next
End Sub

Public Sub decrypt(buff() As Byte)
    Dim i As Long, j As Long, k As Long, m As Long
    Dim a(7) As Long, b(7) As Long
    Dim x() As Long, y() As Long, t() As Long
    
    For i = 0 To m_Nb - 1
        j = i * 4
        a(i) = PackFrom(buff, j)
        a(i) = a(i) Xor m_rkey(i)
    Next
    
    k = m_Nb
    x = a
    y = b
    
    For i = 1 To m_Nr - 1
        For j = 0 To m_Nb - 1
            m = j * 3
            y(j) = m_rkey(k) Xor m_rtable(x(j) And m_lOnBits(7)) Xor _
                RotateLeft(m_rtable(RShift(x(m_ri(m)), 8) And m_lOnBits(7)), 8) Xor _
                RotateLeft(m_rtable(RShift(x(m_ri(m + 1)), 16) And m_lOnBits(7)), 16) Xor _
                RotateLeft(m_rtable(RShift(x(m_ri(m + 2)), 24) And m_lOnBits(7)), 24)
            k = k + 1
        Next
        t = x
        x = y
        y = t
    Next
    
    For j = 0 To m_Nb - 1
        m = j * 3
        
        y(j) = m_rkey(k) Xor m_rbsub(x(j) And m_lOnBits(7)) Xor _
            RotateLeft(m_rbsub(RShift(x(m_ri(m)), 8) And m_lOnBits(7)), 8) Xor _
            RotateLeft(m_rbsub(RShift(x(m_ri(m + 1)), 16) And m_lOnBits(7)), 16) Xor _
            RotateLeft(m_rbsub(RShift(x(m_ri(m + 2)), 24) And m_lOnBits(7)), 24)
        k = k + 1
    Next
    
    For i = 0 To m_Nb - 1
        j = i * 4
        
        UnpackFrom y(i), buff, j
        x(i) = 0
        y(i) = 0
    Next
End Sub

Private Function IsInitialized(vArray)
    On Error Resume Next
    
    IsInitialized = IsNumeric(UBound(vArray))
End Function

Private Sub CopyBytesASP(bytDest() As Byte, lDestStart As Long, bytSource() As Byte, lSourceStart As Long, lLength As Long)
    Dim lCount
    
    lCount = 0
    Do
        bytDest(lDestStart + lCount) = bytSource(lSourceStart + lCount)
        lCount = lCount + 1
    Loop Until lCount = lLength
End Sub

Public Function EncryptData(bytMessage() As Byte, bytPassword() As Byte) As Byte()
    Dim bytKey(31) As Byte, bytIn() As Byte, bytOut() As Byte, bytTemp(31) As Byte
    Dim lCount As Long, lLength As Long, lEncodedLength As Long
    Dim bytLen(3) As Byte
    Dim lPosition As Long
    
    If Not IsInitialized(bytMessage) Then
        Exit Function
    End If
    If Not IsInitialized(bytPassword) Then
        Exit Function
    End If
    
    For lCount = 0 To UBound(bytPassword)
        bytKey(lCount) = bytPassword(lCount)
        If lCount = 31 Then
            Exit For
        End If
    Next
    
    gentables
    gkey 8, 8, bytKey
    
    lLength = UBound(bytMessage) + 1
    lEncodedLength = lLength
    
    If lEncodedLength Mod 32 <> 0 Then
        lEncodedLength = lEncodedLength + 32 - (lEncodedLength Mod 32)
    End If
    ReDim bytIn(lEncodedLength - 1)
    ReDim bytOut(lEncodedLength - 1)

    CopyBytesASP bytIn, 0, bytMessage, 0, lLength
    For lCount = 0 To lEncodedLength - 1 Step 32
        CopyBytesASP bytTemp, 0, bytIn, lCount, 32
        encrypt bytTemp
        CopyBytesASP bytOut, lCount, bytTemp, 0, 32
    Next
    
    EncryptData = bytOut
End Function

Public Function DecryptData(bytIn() As Byte, bytPassword() As Byte) As Byte()
    Dim bytMessage() As Byte, bytKey(31) As Byte, bytOut() As Byte, bytTemp(31) As Byte
    Dim lCount As Long, lLength As Long, lEncodedLength As Long
    Dim bytLen(3) As Byte
    Dim lPosition As Long
    
    If Not IsInitialized(bytIn) Then
        Exit Function
    End If
    If Not IsInitialized(bytPassword) Then
        Exit Function
    End If
    
    lEncodedLength = UBound(bytIn) + 1
    
    If lEncodedLength Mod 32 <> 0 Then
        Exit Function
    End If
    
    For lCount = 0 To UBound(bytPassword)
        bytKey(lCount) = bytPassword(lCount)
        If lCount = 31 Then
            Exit For
        End If
    Next
    
    gentables
    gkey 8, 8, bytKey
    ReDim bytOut(lEncodedLength - 1)
    
    For lCount = 0 To lEncodedLength - 1 Step 32
        CopyBytesASP bytTemp, 0, bytIn, lCount, 32
        decrypt bytTemp
        CopyBytesASP bytOut, lCount, bytTemp, 0, 32
    Next
    lLength = 32
    
    ReDim bytMessage(lLength - 1)
    CopyBytesASP bytMessage, 0, bytOut, 0, lLength
    
    DecryptData = bytMessage
End Function

