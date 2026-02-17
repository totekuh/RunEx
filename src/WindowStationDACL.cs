using System;
using System.Text;
using System.Runtime.InteropServices;

public class WindowStationDACL{

    private IntPtr hWinsta;
    private IntPtr hDesktop;
    private IntPtr userSid;

    private IntPtr GetUserSid(string domain, string username){
        IntPtr userSid = IntPtr.Zero;
        string fqan = "";//Fully qualified account names
        byte [] Sid = null;
        uint cbSid = 0;
        StringBuilder referencedDomainName = new StringBuilder();
        uint cchReferencedDomainName = (uint)referencedDomainName.Capacity;
        NativeMethods.SID_NAME_USE sidUse;
        int err = NativeMethods.NO_ERROR;

        if(domain != "" && domain != ".")
            fqan = domain + "\\" + username;
        else
            fqan = username;

        if (!NativeMethods.LookupAccountName(null,fqan,Sid,ref cbSid,referencedDomainName,ref cchReferencedDomainName,out sidUse))
        {
            err = Marshal.GetLastWin32Error();
            if (err == NativeMethods.ERROR_INSUFFICIENT_BUFFER || err == NativeMethods.ERROR_INVALID_FLAGS)
            {
                Sid = new byte[cbSid];
                referencedDomainName.EnsureCapacity((int)cchReferencedDomainName);
                err = NativeMethods.NO_ERROR;
                if (!NativeMethods.LookupAccountName(null,fqan,Sid,ref cbSid,referencedDomainName,ref cchReferencedDomainName,out sidUse))
                    err = Marshal.GetLastWin32Error();
            }
        }
        else{
            string error = "The username " + fqan + " has not been found. ";
            throw new RunExException(error + "LookupAccountName", true);
        }
        if (err == 0)
        {
            userSid = Marshal.AllocHGlobal((int)cbSid);
            Marshal.Copy(Sid, 0, userSid, (int)cbSid);
        }
        else{
            string error = "The username " + fqan + " has not been found. ";
            throw new RunExException(error + "LookupAccountName", true);
        }
        return userSid;
    }

    //Big thanks to Vanara project
    //https://github.com/dahall/Vanara/blob/9771eadebc874cfe876011c9d6588aefb62626d9/PInvoke/Security/AdvApi32/SecurityBaseApi.cs#L4656
    private void AddAllowedAceToDACL(IntPtr pDacl, NativeMethods.ACCESS_MASK mask, byte aceFlags, uint aceSize){
        int offset = Marshal.SizeOf(typeof(NativeMethods.ACCESS_ALLOWED_ACE)) - Marshal.SizeOf(typeof(uint));
        NativeMethods.ACE_HEADER AceHeader = new NativeMethods.ACE_HEADER();
        AceHeader.AceType = NativeMethods.ACCESS_ALLOWED_ACE_TYPE;
        AceHeader.AceFlags = aceFlags;
        AceHeader.AceSize = (short)aceSize;
        IntPtr pNewAcePtr = Marshal.AllocHGlobal((int)aceSize);
        NativeMethods.ACCESS_ALLOWED_ACE pNewAceStruct = new NativeMethods.ACCESS_ALLOWED_ACE();
        pNewAceStruct.Header = AceHeader;
        pNewAceStruct.Mask = mask;
        Marshal.StructureToPtr(pNewAceStruct, pNewAcePtr, false);
        IntPtr sidStartPtr = new IntPtr(pNewAcePtr.ToInt64() + offset);
        if (!NativeMethods.CopySid((uint)NativeMethods.GetLengthSid(this.userSid), sidStartPtr, this.userSid))
            throw new RunExException("CopySid", true);
        if (!NativeMethods.AddAce(pDacl, NativeMethods.ACL_REVISION, NativeMethods.MAXDWORD, pNewAcePtr, aceSize))
            throw new RunExException("AddAce", true);
        Marshal.FreeHGlobal(pNewAcePtr);
    }

    private void AddAceToObject(IntPtr hObject, NativeMethods.ACCESS_MASK[] masks, byte[] aceFlags){
        uint cbSd = 0;
        bool fDaclPresent = false;
        bool fDaclExist = false;
        IntPtr pDacl = IntPtr.Zero;
        uint cbDacl = 0;
        IntPtr pSd = IntPtr.Zero;
        IntPtr pNewSd = IntPtr.Zero;
        uint cbNewDacl = 0;
        uint cbNewAce = 0;
        IntPtr pNewDacl = IntPtr.Zero;
        uint numNewAces = (uint)masks.Length;

        NativeMethods.ACL_SIZE_INFORMATION aclSizeInfo = new NativeMethods.ACL_SIZE_INFORMATION();
        NativeMethods.SECURITY_INFORMATION si = NativeMethods.SECURITY_INFORMATION.DACL_SECURITY_INFORMATION;
        // Get required buffer size and allocate the SECURITY_DESCRIPTOR buffer.
        if (!NativeMethods.GetUserObjectSecurity(hObject, ref si, pSd, 0, out cbSd))
        {
            if (Marshal.GetLastWin32Error() != NativeMethods.ERROR_INSUFFICIENT_BUFFER)
            {
                throw new RunExException("GetUserObjectSecurity 1 size", true);
            }
        }
        pSd = Marshal.AllocHGlobal((int)cbSd);
        // Obtain the security descriptor for the object.
        if (!NativeMethods.GetUserObjectSecurity(hObject, ref si, pSd, cbSd, out cbSd))
        {
            throw new RunExException("GetUserObjectSecurity 2", true);
        }
        // Get the DACL from the security descriptor.
        if (!NativeMethods.GetSecurityDescriptorDacl(pSd, out fDaclPresent, ref pDacl, out fDaclExist))
        {
            throw new RunExException("GetSecurityDescriptorDacl", true);
        }
        RunExMainClass.VerboseLog("DACL: present=" + fDaclPresent + ", existing ACL ptr=" + (pDacl != IntPtr.Zero));
        // Get the size information of the DACL.
        if (pDacl == IntPtr.Zero)
        {
            cbDacl = 0;
        }
        else
        {
            if (!NativeMethods.GetAclInformation(pDacl, ref aclSizeInfo, (uint)Marshal.SizeOf(typeof(NativeMethods.ACL_SIZE_INFORMATION)), NativeMethods.ACL_INFORMATION_CLASS.AclSizeInformation))
            {
                throw new RunExException("GetAclInformation", true);
            }
            cbDacl = aclSizeInfo.AclBytesInUse;
            RunExMainClass.VerboseLog("DACL: existing ACE count=" + aclSizeInfo.AceCount + ", bytes in use=" + cbDacl);
        }

        // Allocate memory for the new security descriptor.
        pNewSd = Marshal.AllocHGlobal((int)cbSd);
        // Initialize the new security descriptor.
        if (!NativeMethods.InitializeSecurityDescriptor(pNewSd, NativeMethods.SECURITY_DESCRIPTOR_REVISION))
        {
            throw new RunExException("InitializeSecurityDescriptor", true);
        }

        // Compute the size of a DACL to be added to the new security descriptor.
        cbNewAce = (uint)Marshal.SizeOf(typeof(NativeMethods.ACCESS_ALLOWED_ACE)) + (uint)NativeMethods.GetLengthSid(this.userSid) - (uint)Marshal.SizeOf(typeof(uint));
        if(cbDacl == 0)
            cbNewDacl =  8 + (cbNewAce * numNewAces);//8 = sizeof(ACL)
        else
            cbNewDacl = cbDacl + (cbNewAce * numNewAces);
        RunExMainClass.VerboseLog("DACL: new ACL size=" + cbNewDacl + ", adding " + numNewAces + " ACE(s)");

        // Allocate memory for the new DACL.
        pNewDacl = Marshal.AllocHGlobal((int)cbNewDacl);
        // Initialize the new DACL.
        if (!NativeMethods.InitializeAcl(pNewDacl, cbNewDacl, NativeMethods.ACL_REVISION))
        {
            throw new RunExException("InitializeAcl", true);
        }

        // If the original DACL is present, copy it to the new DACL.
        if (fDaclPresent)
        {
            // Copy the ACEs to the new DACL.
            for (int dwIndex = 0; dwIndex < aclSizeInfo.AceCount; dwIndex++)
            {
                IntPtr pTempAce = IntPtr.Zero;
                // Get an ACE.
                if (!NativeMethods.GetAce(pDacl, dwIndex, out pTempAce))
                {
                    throw new RunExException("GetAce", true);
                }
                NativeMethods.ACE_HEADER pTempAceStruct = (NativeMethods.ACE_HEADER)Marshal.PtrToStructure(pTempAce, typeof(NativeMethods.ACE_HEADER));
                // Add the ACE to the new ACL.
                if (!NativeMethods.AddAce(pNewDacl, NativeMethods.ACL_REVISION, NativeMethods.MAXDWORD, pTempAce, (uint)pTempAceStruct.AceSize))
                {
                    throw new RunExException("AddAce", true);
                }
            }
        }

        // Add new ACEs to the new DACL.
        for (int i = 0; i < numNewAces; i++)
            AddAllowedAceToDACL(pNewDacl, masks[i], aceFlags[i], cbNewAce);

        // Assign the new DACL to the new security descriptor.
        if (!NativeMethods.SetSecurityDescriptorDacl(pNewSd, true, pNewDacl, false))
        {
            throw new RunExException("SetSecurityDescriptorDacl", true);
        }
        //  Set the new security descriptor for the object.
        if (!NativeMethods.SetUserObjectSecurity(hObject, ref si, pNewSd))
        {
            throw new RunExException("SetUserObjectSecurity", true);
        }

        Marshal.FreeHGlobal(pSd);
        Marshal.FreeHGlobal(pNewSd);
        Marshal.FreeHGlobal(pNewDacl);
    }

    private void AddAceToWindowStation(){
        AddAceToObject(this.hWinsta,
            new NativeMethods.ACCESS_MASK[] { NativeMethods.ACCESS_MASK.GENERIC_ACCESS, NativeMethods.ACCESS_MASK.WINSTA_ALL },
            new byte[] { (byte)(NativeMethods.CONTAINER_INHERIT_ACE | NativeMethods.INHERIT_ONLY_ACE | NativeMethods.OBJECT_INHERIT_ACE), NativeMethods.NO_PROPAGATE_INHERIT_ACE });
    }

    private void AddAceToDesktop(){
        AddAceToObject(this.hDesktop,
            new NativeMethods.ACCESS_MASK[] { NativeMethods.ACCESS_MASK.DESKTOP_ALL },
            new byte[] { 0 });
    }

    public WindowStationDACL()
    {
        this.hWinsta = IntPtr.Zero;
        this.hDesktop = IntPtr.Zero;
        this.userSid = IntPtr.Zero;
    }

    public string AddAclToActiveWindowStation(string domain, string username, int logonType){
        string lpDesktop = "";
        byte[] stationNameBytes = new byte[256];
        string stationName = "";
        uint lengthNeeded = 0;
        RunExMainClass.VerboseLog("DACL: getting current window station");
        IntPtr hWinstaSave = NativeMethods.GetProcessWindowStation();
        if(hWinstaSave == IntPtr.Zero)
        {
            throw new RunExException("GetProcessWindowStation", true);
        }
        if(!NativeMethods.GetUserObjectInformation(hWinstaSave, NativeMethods.UOI_NAME, stationNameBytes, 256, out lengthNeeded)){
            throw new RunExException("GetUserObjectInformation", true);
        }
        stationName = Encoding.Default.GetString(stationNameBytes).Substring(0, (int)lengthNeeded-1);
        RunExMainClass.VerboseLog("DACL: station name: " + stationName);
        // this should be avoided with the LOGON32_LOGON_NEW_CREDENTIALS logon type or some bug can happen in LookupAccountName()
        if (logonType != 9)
        {
            RunExMainClass.VerboseLog("DACL: opening window station for DACL modification");
            this.hWinsta = NativeMethods.OpenWindowStation(stationName, false, NativeMethods.ACCESS_MASK.READ_CONTROL | NativeMethods.ACCESS_MASK.WRITE_DAC);
            if (this.hWinsta == IntPtr.Zero)
            {
                throw new RunExException("OpenWindowStation", true);
            }
            if (!NativeMethods.SetProcessWindowStation(this.hWinsta))
            {
                throw new RunExException("SetProcessWindowStation hWinsta", true);
            }
            this.hDesktop = NativeMethods.OpenDesktop("Default", 0, false, NativeMethods.ACCESS_MASK.READ_CONTROL | NativeMethods.ACCESS_MASK.WRITE_DAC | NativeMethods.ACCESS_MASK.DESKTOP_WRITEOBJECTS | NativeMethods.ACCESS_MASK.DESKTOP_READOBJECTS);
            if (!NativeMethods.SetProcessWindowStation(hWinstaSave))
            {
                throw new RunExException("SetProcessWindowStation hWinstaSave", true);
            }
            if (this.hWinsta == IntPtr.Zero)
            {
                throw new RunExException("OpenDesktop", true);
            }
            RunExMainClass.VerboseLog("DACL: looking up SID for user");
            this.userSid = GetUserSid(domain, username);
            RunExMainClass.VerboseLog("DACL: adding ACE to window station");
            AddAceToWindowStation();
            RunExMainClass.VerboseLog("DACL: adding ACE to desktop");
            AddAceToDesktop();
        }
        lpDesktop = stationName + "\\Default";
        return lpDesktop;
    }

    public void CleanupHandles()
    {
        if(this.hWinsta != IntPtr.Zero) NativeMethods.CloseWindowStation(this.hWinsta);
        if(this.hDesktop != IntPtr.Zero) NativeMethods.CloseDesktop(this.hDesktop);
        if(this.userSid != IntPtr.Zero) NativeMethods.FreeSid(this.userSid);
    }
}
