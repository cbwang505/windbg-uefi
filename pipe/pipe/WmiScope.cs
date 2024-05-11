using System;
using System.Collections.Generic;
using System.Linq;
using System.Management;
using System.Reflection;

namespace pipe
{
    [AttributeUsage(AttributeTargets.Property, AllowMultiple = false, Inherited = true)]
    public class WmiKeyAttribute : Attribute
    {
        public WmiKeyAttribute() { }
    }
    [AttributeUsage(AttributeTargets.Interface | AttributeTargets.Class, AllowMultiple = false, Inherited = false)]
    public sealed class WmiClassNameAttribute : Attribute
    {
        public string ClassName { get; }
        public string Namespace { get; }

        public WmiClassNameAttribute(string className, string nameSpace)
        {
            if (string.IsNullOrWhiteSpace(className))
            {
                throw new ArgumentNullException(nameof(className));
            }
            ClassName = className;
            Namespace = nameSpace;
        }
    }
    public abstract class IWmiObject
    {
        public ManagementBaseObject __Instance { get; protected set; }

        public T[] GetAssociated<T>(string association)
        {
            try
            {
                var name = WmiClassImpl.ClassName<T>();
                ManagementObjectCollection collection = ((ManagementObject)__Instance).GetRelated(
                    name.ClassName,
                    association,
                    null,
                    null,
                    null,
                    null,
                    false,
                    null);
                return WmiClassImpl.FromInstances<T>(collection);
            }
            catch (Exception)
            {
                return new T[0];
            }
        }
    }
    public class WmiClassImpl
    {
        public static WmiClassNameAttribute ClassName<T>()
        {
            Attribute attribute = typeof(T).GetCustomAttribute(typeof(WmiClassNameAttribute),true);
            if (attribute == null)
            {
                throw new InvalidOperationException("Template interface requires WmiClassName attribute");
            }

            return (WmiClassNameAttribute)attribute;
        }

        public static T GetProperty<T>(ManagementBaseObject instance, string propertyName)
        {
            if (instance == null)
            {
                return default;
            }

            try
            {
                object value = instance.GetPropertyValue(propertyName);
                if (value == null)
                {
                    return default;
                }

                return ConvertFromObject<T>(instance.GetPropertyValue(propertyName));
            }
            catch (Exception)
            {
                return default;
            }
        }

        private static T ConvertFromObject<T>(object value)
        {
            Type t = typeof(T);
            if (t.IsArray)
            {
                Type et = t.GetElementType();
                if (et == null)
                {
                    throw new ArgumentException();
                }

                var methodName = typeof(IWmiObject).IsAssignableFrom(et)
                    ? nameof(ConvertFromObjectArray)
                    : nameof(ConvertFromTypedArray);
                object result = typeof(WmiClassImpl).GetMethod(methodName)
                    ?.MakeGenericMethod(et)
                    ?.Invoke(null, new object[] { value });
                if (result == null)
                {
                    throw new NullReferenceException();
                }

                return (T)result;
            }

            if (t == typeof(DateTime))
            {
                value = ManagementDateTimeConverter.ToDateTime((string)value);
            }
            else if (t.IsEnum)
            {
                if (t.GetEnumUnderlyingType() != value.GetType())
                {
                    throw new InvalidCastException();
                }
            }
            else if (typeof(IWmiObject).IsAssignableFrom(t))
            {
                string path = value as string;
                if (path != null)
                {
                    value = new ManagementObject(path);
                }

                T instance = WmiClassGenerator.CreateInstance<T>((ManagementBaseObject)value);
                value = (T)instance;
            }

            return (T)value;
        }

        public static object ConvertFromObjectArray<T>(object[] array)
        {
            T[] ret = new T[array.Length];
            for (int i = 0; i < array.Length; ++i)
            {
                ret[i] = ConvertFromObject<T>(array[i]);
            }

            return ret;
        }

        public static object ConvertFromTypedArray<T>(T[] array)
        {
            T[] ret = new T[array.Length];
            for (int i = 0; i < array.Length; ++i)
            {
                ret[i] = ConvertFromObject<T>(array[i]);
            }

            return ret;
        }

        public static void SetProperty<T>(ManagementBaseObject instance, string propertyName, object value)
        {
            try
            {
                if (value == null)
                {
                    instance.Properties.Remove(propertyName);
                }
                else
                {
                    Type t = value.GetType();
                    if (t.IsArray)
                    {
                        Type et = t.GetElementType();
                        if (et == null)
                        {
                            throw new NullReferenceException();
                        }

                        if (typeof(IWmiObject).IsAssignableFrom(et))
                        {
                            value = ToInstanceArray((IWmiObject[])value);
                        }
                    }
                    else if (t == typeof(DateTime))
                    {
                        value = ManagementDateTimeConverter.ToDmtfDateTime((DateTime)value);
                    }

                    instance.SetPropertyValue(propertyName, (T)value);
                }
            }
            catch (Exception)
            {
            }
        }

        public static ManagementBaseObject MethodParameters(ManagementBaseObject instance, string methodName)
        {
            ManagementClass wmiClass = new ManagementClass(instance.ClassPath);
            return wmiClass.GetMethodParameters(methodName);
        }

        public static T[] FromInstances<T>(ManagementObjectCollection instances)
        {
            if (instances == null)
            {
                return new T[0];
            }

            T[] ret = new T[instances.Count];
            var enumerator = instances.GetEnumerator();
            for (int i = 0; enumerator.MoveNext(); ++i)
            {
                ret[i] = WmiClassGenerator.CreateInstance<T>(enumerator.Current);
            }

            return ret;
        }

        public static ManagementBaseObject[] ToInstanceArray(IEnumerable<IWmiObject> instances)
        {
            if (instances == null)
            {
                return new ManagementBaseObject[0];
            }

            ManagementBaseObject[] ret = new ManagementBaseObject[instances.Count()];
            var enumerator = instances.GetEnumerator();
            for (int i = 0; enumerator.MoveNext(); ++i)
            {
                ret[i] = enumerator.Current.__Instance;
            }

            return ret;
        }
    }

    public class WmiClassGenerator
    {
        public static T CreateInstance<T>(ManagementBaseObject instance)
        {
            object result = Activator.CreateInstance(typeof(T), new object[] { instance });
            if (result == null)
            {
                throw new NullReferenceException();
            }
            return (T)result;
        }
    }
    public class WmiScope
    {
        public ManagementScope Scope { get; }

        public WmiScope(string nameSpace)
        {
            var options = new ConnectionOptions();
            Scope = new ManagementScope(nameSpace, options);
            Scope.Connect();
        }

        public T GetInstance<T>()
        {
            return GetInstances<T>().FirstOrDefault();
        }

        public IEnumerable<T> GetInstances<T>()
        {
            var name = WmiClassImpl.ClassName<T>();
            var wmiClass = new ManagementClass(Scope, new ManagementPath(name.ClassName), new ObjectGetOptions());
            return GenList<T>(wmiClass.GetInstances());
        }

        public IEnumerable<T> QueryInstances<T>(string query)
        {
            var searcher = new ManagementObjectSearcher(Scope, new WqlObjectQuery(query));
            return GenList<T>(searcher.Get());
        }

      

        private IEnumerable<T> GenList<T>(ManagementObjectCollection collection)
        {
            var enumerator = collection.GetEnumerator();
            var list = new List<T>();
            while (enumerator.MoveNext())
            {
                list.Add(WmiClassGenerator.CreateInstance<T>((ManagementObject)enumerator.Current));
            }
            return list;
        }
    }

    [WmiClassName("Msvm_ConcreteJob", @"root\virtualization\v2")]
    public class IMsvm_ConcreteJob : IWmiObject
    {
        public IMsvm_ConcreteJob(ManagementBaseObject instance) { __Instance = instance; }

        public string Caption { get => WmiClassImpl.GetProperty<string>(__Instance, "Caption"); set => WmiClassImpl.SetProperty<string>(__Instance, "Caption", value); }
        public string Description { get => WmiClassImpl.GetProperty<string>(__Instance, "Description"); set => WmiClassImpl.SetProperty<string>(__Instance, "Description", value); }
        public string ElementName { get => WmiClassImpl.GetProperty<string>(__Instance, "ElementName"); set => WmiClassImpl.SetProperty<string>(__Instance, "ElementName", value); }
        [WmiKey] public string InstanceID { get => WmiClassImpl.GetProperty<string>(__Instance, "InstanceID"); set => WmiClassImpl.SetProperty<string>(__Instance, "InstanceID", value); }
        public ushort CommunicationStatus { get => WmiClassImpl.GetProperty<ushort>(__Instance, "CommunicationStatus"); set => WmiClassImpl.SetProperty<ushort>(__Instance, "CommunicationStatus", value); }
        public ushort DetailedStatus { get => WmiClassImpl.GetProperty<ushort>(__Instance, "DetailedStatus"); set => WmiClassImpl.SetProperty<ushort>(__Instance, "DetailedStatus", value); }
        public ushort HealthState { get => WmiClassImpl.GetProperty<ushort>(__Instance, "HealthState"); set => WmiClassImpl.SetProperty<ushort>(__Instance, "HealthState", value); }
        public DateTime InstallDate { get => WmiClassImpl.GetProperty<DateTime>(__Instance, "InstallDate"); set => WmiClassImpl.SetProperty<DateTime>(__Instance, "InstallDate", value); }
        public string Name { get => WmiClassImpl.GetProperty<string>(__Instance, "Name"); set => WmiClassImpl.SetProperty<string>(__Instance, "Name", value); }
        public ushort OperatingStatus { get => WmiClassImpl.GetProperty<ushort>(__Instance, "OperatingStatus"); set => WmiClassImpl.SetProperty<ushort>(__Instance, "OperatingStatus", value); }
        public ushort[] OperationalStatus { get => WmiClassImpl.GetProperty<ushort[]>(__Instance, "OperationalStatus"); set => WmiClassImpl.SetProperty<ushort[]>(__Instance, "OperationalStatus", value); }
        public ushort PrimaryStatus { get => WmiClassImpl.GetProperty<ushort>(__Instance, "PrimaryStatus"); set => WmiClassImpl.SetProperty<ushort>(__Instance, "PrimaryStatus", value); }
        public string Status { get => WmiClassImpl.GetProperty<string>(__Instance, "Status"); set => WmiClassImpl.SetProperty<string>(__Instance, "Status", value); }
        public string[] StatusDescriptions { get => WmiClassImpl.GetProperty<string[]>(__Instance, "StatusDescriptions"); set => WmiClassImpl.SetProperty<string[]>(__Instance, "StatusDescriptions", value); }
        public bool DeleteOnCompletion { get => WmiClassImpl.GetProperty<bool>(__Instance, "DeleteOnCompletion"); set => WmiClassImpl.SetProperty<bool>(__Instance, "DeleteOnCompletion", value); }
        public DateTime ElapsedTime { get => WmiClassImpl.GetProperty<DateTime>(__Instance, "ElapsedTime"); set => WmiClassImpl.SetProperty<DateTime>(__Instance, "ElapsedTime", value); }
        public ushort ErrorCode { get => WmiClassImpl.GetProperty<ushort>(__Instance, "ErrorCode"); set => WmiClassImpl.SetProperty<ushort>(__Instance, "ErrorCode", value); }
        public string ErrorDescription { get => WmiClassImpl.GetProperty<string>(__Instance, "ErrorDescription"); set => WmiClassImpl.SetProperty<string>(__Instance, "ErrorDescription", value); }
        public uint JobRunTimes { get => WmiClassImpl.GetProperty<uint>(__Instance, "JobRunTimes"); set => WmiClassImpl.SetProperty<uint>(__Instance, "JobRunTimes", value); }
        public string JobStatus { get => WmiClassImpl.GetProperty<string>(__Instance, "JobStatus"); set => WmiClassImpl.SetProperty<string>(__Instance, "JobStatus", value); }
        public ushort LocalOrUtcTime { get => WmiClassImpl.GetProperty<ushort>(__Instance, "LocalOrUtcTime"); set => WmiClassImpl.SetProperty<ushort>(__Instance, "LocalOrUtcTime", value); }
        public string Notify { get => WmiClassImpl.GetProperty<string>(__Instance, "Notify"); set => WmiClassImpl.SetProperty<string>(__Instance, "Notify", value); }
        public string OtherRecoveryAction { get => WmiClassImpl.GetProperty<string>(__Instance, "OtherRecoveryAction"); set => WmiClassImpl.SetProperty<string>(__Instance, "OtherRecoveryAction", value); }
        public string Owner { get => WmiClassImpl.GetProperty<string>(__Instance, "Owner"); set => WmiClassImpl.SetProperty<string>(__Instance, "Owner", value); }
        public ushort PercentComplete { get => WmiClassImpl.GetProperty<ushort>(__Instance, "PercentComplete"); set => WmiClassImpl.SetProperty<ushort>(__Instance, "PercentComplete", value); }
        public uint Priority { get => WmiClassImpl.GetProperty<uint>(__Instance, "Priority"); set => WmiClassImpl.SetProperty<uint>(__Instance, "Priority", value); }
        public ushort RecoveryAction { get => WmiClassImpl.GetProperty<ushort>(__Instance, "RecoveryAction"); set => WmiClassImpl.SetProperty<ushort>(__Instance, "RecoveryAction", value); }
        public sbyte RunDay { get => WmiClassImpl.GetProperty<sbyte>(__Instance, "RunDay"); set => WmiClassImpl.SetProperty<sbyte>(__Instance, "RunDay", value); }
        public sbyte RunDayOfWeek { get => WmiClassImpl.GetProperty<sbyte>(__Instance, "RunDayOfWeek"); set => WmiClassImpl.SetProperty<sbyte>(__Instance, "RunDayOfWeek", value); }
        public byte RunMonth { get => WmiClassImpl.GetProperty<byte>(__Instance, "RunMonth"); set => WmiClassImpl.SetProperty<byte>(__Instance, "RunMonth", value); }
        public DateTime RunStartInterval { get => WmiClassImpl.GetProperty<DateTime>(__Instance, "RunStartInterval"); set => WmiClassImpl.SetProperty<DateTime>(__Instance, "RunStartInterval", value); }
        public DateTime ScheduledStartTime { get => WmiClassImpl.GetProperty<DateTime>(__Instance, "ScheduledStartTime"); set => WmiClassImpl.SetProperty<DateTime>(__Instance, "ScheduledStartTime", value); }
        public DateTime StartTime { get => WmiClassImpl.GetProperty<DateTime>(__Instance, "StartTime"); set => WmiClassImpl.SetProperty<DateTime>(__Instance, "StartTime", value); }
        public DateTime TimeSubmitted { get => WmiClassImpl.GetProperty<DateTime>(__Instance, "TimeSubmitted"); set => WmiClassImpl.SetProperty<DateTime>(__Instance, "TimeSubmitted", value); }
        public DateTime UntilTime { get => WmiClassImpl.GetProperty<DateTime>(__Instance, "UntilTime"); set => WmiClassImpl.SetProperty<DateTime>(__Instance, "UntilTime", value); }
        public ushort JobState { get => WmiClassImpl.GetProperty<ushort>(__Instance, "JobState"); set => WmiClassImpl.SetProperty<ushort>(__Instance, "JobState", value); }
        public DateTime TimeBeforeRemoval { get => WmiClassImpl.GetProperty<DateTime>(__Instance, "TimeBeforeRemoval"); set => WmiClassImpl.SetProperty<DateTime>(__Instance, "TimeBeforeRemoval", value); }
        public DateTime TimeOfLastStateChange { get => WmiClassImpl.GetProperty<DateTime>(__Instance, "TimeOfLastStateChange"); set => WmiClassImpl.SetProperty<DateTime>(__Instance, "TimeOfLastStateChange", value); }
        public bool? Cancellable { get => WmiClassImpl.GetProperty<bool>(__Instance, "Cancellable"); set => WmiClassImpl.SetProperty<bool>(__Instance, "Cancellable", value); }
        public string ErrorSummaryDescription { get => WmiClassImpl.GetProperty<string>(__Instance, "ErrorSummaryDescription"); set => WmiClassImpl.SetProperty<string>(__Instance, "ErrorSummaryDescription", value); }
        public ushort JobType { get => WmiClassImpl.GetProperty<ushort>(__Instance, "JobType"); set => WmiClassImpl.SetProperty<ushort>(__Instance, "JobType", value); }

        public uint KillJob(bool DeleteOnKill)
        {
            ManagementBaseObject inParams = WmiClassImpl.MethodParameters(__Instance, "KillJob");
            WmiClassImpl.SetProperty<bool>(inParams, "DeleteOnKill", DeleteOnKill);
            ManagementBaseObject outParams = ((ManagementObject)__Instance).InvokeMethod("KillJob", inParams, null);
            return WmiClassImpl.GetProperty<uint>(outParams, "ReturnValue");
        }
        public uint RequestStateChange(ushort RequestedState, DateTime TimeoutPeriod)
        {
            ManagementBaseObject inParams = WmiClassImpl.MethodParameters(__Instance, "RequestStateChange");
            WmiClassImpl.SetProperty<ushort>(inParams, "RequestedState", RequestedState);
            WmiClassImpl.SetProperty<DateTime>(inParams, "TimeoutPeriod", TimeoutPeriod);
            ManagementBaseObject outParams = ((ManagementObject)__Instance).InvokeMethod("RequestStateChange", inParams, null);
            return WmiClassImpl.GetProperty<uint>(outParams, "ReturnValue");
        }
        public uint GetError(out string Error)
        {
            ManagementBaseObject inParams = WmiClassImpl.MethodParameters(__Instance, "GetError");
            ManagementBaseObject outParams = ((ManagementObject)__Instance).InvokeMethod("GetError", inParams, null);
            Error = WmiClassImpl.GetProperty<string>(outParams, "Error");
            return WmiClassImpl.GetProperty<uint>(outParams, "ReturnValue");
        }
        public uint GetErrorEx(out string[] Errors)
        {
            ManagementBaseObject inParams = WmiClassImpl.MethodParameters(__Instance, "GetErrorEx");
            ManagementBaseObject outParams = ((ManagementObject)__Instance).InvokeMethod("GetErrorEx", inParams, null);
            Errors = WmiClassImpl.GetProperty<string[]>(outParams, "Errors");
            return WmiClassImpl.GetProperty<uint>(outParams, "ReturnValue");
        }
    }
    [WmiClassName("Msvm_ComputerSystem", @"root\virtualization\v2")]
    public class IMsvm_ComputerSystem : IWmiObject
    {
        public IMsvm_ComputerSystem(ManagementBaseObject instance) { __Instance = instance; }

        public enum SystemState : ushort
        {
            Unknown = 0,
            Other = 1,
            Running = 2,
            Off = 3,
            Stopping = 4,
            Saved = 6,
            Paused = 9,
            Starting = 10,
            Reset = 11,
            Saving = 0x8005,
            Pausing = 0x8008,
            Resuming = 0x8009,
            FastSaved = 0x800b,
            FastSaving = 0x800c,
            ForceShutdown = 0x800d,
            ForceReboot = 0x800e,
            Hibernated = 0x800f,
            ComponentServicing = 0x8010
        }

        public enum EnhancedSessionMode : ushort
        {
            AllowedAndAvailable = 2,
            NotAllowed = 3,
            AllowedButUnavailable = 6
        }

        public string Caption { get => WmiClassImpl.GetProperty<string>(__Instance, "Caption"); set => WmiClassImpl.SetProperty<string>(__Instance, "Caption", value); }
        public string Description { get => WmiClassImpl.GetProperty<string>(__Instance, "Description"); set => WmiClassImpl.SetProperty<string>(__Instance, "Description", value); }
        public string ElementName { get => WmiClassImpl.GetProperty<string>(__Instance, "ElementName"); set => WmiClassImpl.SetProperty<string>(__Instance, "ElementName", value); }
        public string InstanceID { get => WmiClassImpl.GetProperty<string>(__Instance, "InstanceID"); set => WmiClassImpl.SetProperty<string>(__Instance, "InstanceID", value); }
        public ushort CommunicationStatus { get => WmiClassImpl.GetProperty<ushort>(__Instance, "CommunicationStatus"); set => WmiClassImpl.SetProperty<ushort>(__Instance, "CommunicationStatus", value); }
        public ushort DetailedStatus { get => WmiClassImpl.GetProperty<ushort>(__Instance, "DetailedStatus"); set => WmiClassImpl.SetProperty<ushort>(__Instance, "DetailedStatus", value); }
        public ushort HealthState { get => WmiClassImpl.GetProperty<ushort>(__Instance, "HealthState"); set => WmiClassImpl.SetProperty<ushort>(__Instance, "HealthState", value); }
        public DateTime InstallDate { get => WmiClassImpl.GetProperty<DateTime>(__Instance, "InstallDate"); set => WmiClassImpl.SetProperty<DateTime>(__Instance, "InstallDate", value); }
        [WmiKey] public string Name { get => WmiClassImpl.GetProperty<string>(__Instance, "Name"); set => WmiClassImpl.SetProperty<string>(__Instance, "Name", value); }
        public ushort OperatingStatus { get => WmiClassImpl.GetProperty<ushort>(__Instance, "OperatingStatus"); set => WmiClassImpl.SetProperty<ushort>(__Instance, "OperatingStatus", value); }
        public ushort[] OperationalStatus { get => WmiClassImpl.GetProperty<ushort[]>(__Instance, "OperationalStatus"); set => WmiClassImpl.SetProperty<ushort[]>(__Instance, "OperationalStatus", value); }
        public ushort PrimaryStatus { get => WmiClassImpl.GetProperty<ushort>(__Instance, "PrimaryStatus"); set => WmiClassImpl.SetProperty<ushort>(__Instance, "PrimaryStatus", value); }
        public string Status { get => WmiClassImpl.GetProperty<string>(__Instance, "Status"); set => WmiClassImpl.SetProperty<string>(__Instance, "Status", value); }
        public string[] StatusDescriptions { get => WmiClassImpl.GetProperty<string[]>(__Instance, "StatusDescriptions"); set => WmiClassImpl.SetProperty<string[]>(__Instance, "StatusDescriptions", value); }
        public ushort[] AvailableRequestedStates { get => WmiClassImpl.GetProperty<ushort[]>(__Instance, "AvailableRequestedStates"); set => WmiClassImpl.SetProperty<ushort[]>(__Instance, "AvailableRequestedStates", value); }
        public ushort EnabledDefault { get => WmiClassImpl.GetProperty<ushort>(__Instance, "EnabledDefault"); set => WmiClassImpl.SetProperty<ushort>(__Instance, "EnabledDefault", value); }
        public SystemState? EnabledState { get => WmiClassImpl.GetProperty<SystemState>(__Instance, "EnabledState"); set => WmiClassImpl.SetProperty<ushort>(__Instance, "EnabledState", value); }
        public string OtherEnabledState { get => WmiClassImpl.GetProperty<string>(__Instance, "OtherEnabledState"); set => WmiClassImpl.SetProperty<string>(__Instance, "OtherEnabledState", value); }
        public ushort RequestedState { get => WmiClassImpl.GetProperty<ushort>(__Instance, "RequestedState"); set => WmiClassImpl.SetProperty<ushort>(__Instance, "RequestedState", value); }
        public DateTime TimeOfLastStateChange { get => WmiClassImpl.GetProperty<DateTime>(__Instance, "TimeOfLastStateChange"); set => WmiClassImpl.SetProperty<DateTime>(__Instance, "TimeOfLastStateChange", value); }
        public ushort TransitioningToState { get => WmiClassImpl.GetProperty<ushort>(__Instance, "TransitioningToState"); set => WmiClassImpl.SetProperty<ushort>(__Instance, "TransitioningToState", value); }
        [WmiKey] public string CreationClassName { get => WmiClassImpl.GetProperty<string>(__Instance, "CreationClassName"); set => WmiClassImpl.SetProperty<string>(__Instance, "CreationClassName", value); }
        public string[] IdentifyingDescriptions { get => WmiClassImpl.GetProperty<string[]>(__Instance, "IdentifyingDescriptions"); set => WmiClassImpl.SetProperty<string[]>(__Instance, "IdentifyingDescriptions", value); }
        public string NameFormat { get => WmiClassImpl.GetProperty<string>(__Instance, "NameFormat"); set => WmiClassImpl.SetProperty<string>(__Instance, "NameFormat", value); }
        public string[] OtherIdentifyingInfo { get => WmiClassImpl.GetProperty<string[]>(__Instance, "OtherIdentifyingInfo"); set => WmiClassImpl.SetProperty<string[]>(__Instance, "OtherIdentifyingInfo", value); }
        public string PrimaryOwnerContact { get => WmiClassImpl.GetProperty<string>(__Instance, "PrimaryOwnerContact"); set => WmiClassImpl.SetProperty<string>(__Instance, "PrimaryOwnerContact", value); }
        public string PrimaryOwnerName { get => WmiClassImpl.GetProperty<string>(__Instance, "PrimaryOwnerName"); set => WmiClassImpl.SetProperty<string>(__Instance, "PrimaryOwnerName", value); }
        public string[] Roles { get => WmiClassImpl.GetProperty<string[]>(__Instance, "Roles"); set => WmiClassImpl.SetProperty<string[]>(__Instance, "Roles", value); }
        public ushort[] Dedicated { get => WmiClassImpl.GetProperty<ushort[]>(__Instance, "Dedicated"); set => WmiClassImpl.SetProperty<ushort[]>(__Instance, "Dedicated", value); }
        public string[] OtherDedicatedDescriptions { get => WmiClassImpl.GetProperty<string[]>(__Instance, "OtherDedicatedDescriptions"); set => WmiClassImpl.SetProperty<string[]>(__Instance, "OtherDedicatedDescriptions", value); }
        public ushort[] PowerManagementCapabilities { get => WmiClassImpl.GetProperty<ushort[]>(__Instance, "PowerManagementCapabilities"); set => WmiClassImpl.SetProperty<ushort[]>(__Instance, "PowerManagementCapabilities", value); }
        public ushort ResetCapability { get => WmiClassImpl.GetProperty<ushort>(__Instance, "ResetCapability"); set => WmiClassImpl.SetProperty<ushort>(__Instance, "ResetCapability", value); }
        public EnhancedSessionMode? EnhancedSessionModeState { get => WmiClassImpl.GetProperty<EnhancedSessionMode>(__Instance, "EnhancedSessionModeState"); set => WmiClassImpl.SetProperty<ushort>(__Instance, "EnhancedSessionModeState", value); }
        public ushort FailedOverReplicationType { get => WmiClassImpl.GetProperty<ushort>(__Instance, "FailedOverReplicationType"); set => WmiClassImpl.SetProperty<ushort>(__Instance, "FailedOverReplicationType", value); }
        public uint HwThreadsPerCoreRealized { get => WmiClassImpl.GetProperty<uint>(__Instance, "HwThreadsPerCoreRealized"); set => WmiClassImpl.SetProperty<uint>(__Instance, "HwThreadsPerCoreRealized", value); }
        public DateTime LastApplicationConsistentReplicationTime { get => WmiClassImpl.GetProperty<DateTime>(__Instance, "LastApplicationConsistentReplicationTime"); set => WmiClassImpl.SetProperty<DateTime>(__Instance, "LastApplicationConsistentReplicationTime", value); }
        public DateTime LastReplicationTime { get => WmiClassImpl.GetProperty<DateTime>(__Instance, "LastReplicationTime"); set => WmiClassImpl.SetProperty<DateTime>(__Instance, "LastReplicationTime", value); }
        public ushort LastReplicationType { get => WmiClassImpl.GetProperty<ushort>(__Instance, "LastReplicationType"); set => WmiClassImpl.SetProperty<ushort>(__Instance, "LastReplicationType", value); }
        public DateTime LastSuccessfulBackupTime { get => WmiClassImpl.GetProperty<DateTime>(__Instance, "LastSuccessfulBackupTime"); set => WmiClassImpl.SetProperty<DateTime>(__Instance, "LastSuccessfulBackupTime", value); }
        public ushort NumberOfNumaNodes { get => WmiClassImpl.GetProperty<ushort>(__Instance, "NumberOfNumaNodes"); set => WmiClassImpl.SetProperty<ushort>(__Instance, "NumberOfNumaNodes", value); }
        public UInt64 OnTimeInMilliseconds { get => WmiClassImpl.GetProperty<UInt64>(__Instance, "OnTimeInMilliseconds"); set => WmiClassImpl.SetProperty<UInt64>(__Instance, "OnTimeInMilliseconds", value); }
        public uint ProcessID { get => WmiClassImpl.GetProperty<uint>(__Instance, "ProcessID"); set => WmiClassImpl.SetProperty<uint>(__Instance, "ProcessID", value); }
        public ushort ReplicationHealth { get => WmiClassImpl.GetProperty<ushort>(__Instance, "ReplicationHealth"); set => WmiClassImpl.SetProperty<ushort>(__Instance, "ReplicationHealth", value); }
        public ushort ReplicationMode { get => WmiClassImpl.GetProperty<ushort>(__Instance, "ReplicationMode"); set => WmiClassImpl.SetProperty<ushort>(__Instance, "ReplicationMode", value); }
        public ushort ReplicationState { get => WmiClassImpl.GetProperty<ushort>(__Instance, "ReplicationState"); set => WmiClassImpl.SetProperty<ushort>(__Instance, "ReplicationState", value); }
        public DateTime TimeOfLastConfigurationChange { get => WmiClassImpl.GetProperty<DateTime>(__Instance, "TimeOfLastConfigurationChange"); set => WmiClassImpl.SetProperty<DateTime>(__Instance, "TimeOfLastConfigurationChange", value); }

        public uint RequestStateChange(ushort RequestedState, out IMsvm_ConcreteJob Job)
        {
            ManagementBaseObject inParams = WmiClassImpl.MethodParameters(__Instance, "RequestStateChange");
            WmiClassImpl.SetProperty<ushort>(inParams, "RequestedState", RequestedState);
            ManagementBaseObject outParams = ((ManagementObject)__Instance).InvokeMethod("RequestStateChange", inParams, null);
            Job = WmiClassImpl.GetProperty<IMsvm_ConcreteJob>(outParams, "Job");
            return WmiClassImpl.GetProperty<uint>(outParams, "ReturnValue");
        }
        public uint SetPowerState(uint PowerState, DateTime Time)
        {
            ManagementBaseObject inParams = WmiClassImpl.MethodParameters(__Instance, "SetPowerState");
            WmiClassImpl.SetProperty<uint>(inParams, "PowerState", PowerState);
            WmiClassImpl.SetProperty<DateTime>(inParams, "Time", Time);
            ManagementBaseObject outParams = ((ManagementObject)__Instance).InvokeMethod("SetPowerState", inParams, null);
            return WmiClassImpl.GetProperty<uint>(outParams, "ReturnValue");
        }
        public uint RequestReplicationStateChange(ushort RequestedState, out ManagementBaseObject Job)
        {
            ManagementBaseObject inParams = WmiClassImpl.MethodParameters(__Instance, "RequestReplicationStateChange");
            WmiClassImpl.SetProperty<ushort>(inParams, "RequestedState", RequestedState);
            ManagementBaseObject outParams = ((ManagementObject)__Instance).InvokeMethod("RequestReplicationStateChange", inParams, null);
            Job = WmiClassImpl.GetProperty<ManagementBaseObject>(outParams, "Job");
            return WmiClassImpl.GetProperty<uint>(outParams, "ReturnValue");
        }
        public uint InjectNonMaskableInterrupt(out ManagementBaseObject Job)
        {
            ManagementBaseObject inParams = WmiClassImpl.MethodParameters(__Instance, "InjectNonMaskableInterrupt");
            ManagementBaseObject outParams = ((ManagementObject)__Instance).InvokeMethod("InjectNonMaskableInterrupt", inParams, null);
            Job = WmiClassImpl.GetProperty<ManagementBaseObject>(outParams, "Job");
            return WmiClassImpl.GetProperty<uint>(outParams, "ReturnValue");
        }
        public uint RequestReplicationStateChangeEx(string ReplicationRelationship, ushort RequestedState, out ManagementBaseObject Job)
        {
            ManagementBaseObject inParams = WmiClassImpl.MethodParameters(__Instance, "RequestReplicationStateChangeEx");
            WmiClassImpl.SetProperty<string>(inParams, "ReplicationRelationship", ReplicationRelationship);
            WmiClassImpl.SetProperty<ushort>(inParams, "RequestedState", RequestedState);
            ManagementBaseObject outParams = ((ManagementObject)__Instance).InvokeMethod("RequestReplicationStateChangeEx", inParams, null);
            Job = WmiClassImpl.GetProperty<ManagementBaseObject>(outParams, "Job");
            return WmiClassImpl.GetProperty<uint>(outParams, "ReturnValue");
        }
    }
}