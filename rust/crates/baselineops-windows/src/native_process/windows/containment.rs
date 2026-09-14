use super::{
    OwnedHandle,
    api::{
        AssignProcessToJobObject, CreateJobObjectW, DeleteProcThreadAttributeList, Handle,
        InitializeProcThreadAttributeList, IoCounters, JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JobObjectBasicLimitInformation,
        JobObjectExtendedLimitInformation, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
        SetInformationJobObject, TerminateJobObject, UpdateProcThreadAttribute,
    },
    last_error,
};
use crate::PlatformError;
use std::mem::{size_of, size_of_val};
use std::ptr;

pub(super) struct AttributeList(Vec<usize>);

impl AttributeList {
    pub(super) fn for_handles(handles: &[Handle]) -> Result<Self, PlatformError> {
        let mut bytes = 0_usize;
        let _ = unsafe { InitializeProcThreadAttributeList(ptr::null_mut(), 1, 0, &raw mut bytes) };
        if bytes == 0 {
            return Err(last_error("InitializeProcThreadAttributeList"));
        }
        let mut storage = vec![0_usize; bytes.div_ceil(size_of::<usize>())];
        let attributes = storage.as_mut_ptr().cast();
        initialize_attribute_list(attributes, &raw mut bytes)?;
        update_handle_list(attributes, handles)?;
        Ok(Self(storage))
    }

    pub(super) fn raw(&mut self) -> *mut core::ffi::c_void {
        self.0.as_mut_ptr().cast()
    }
}

impl Drop for AttributeList {
    fn drop(&mut self) {
        unsafe { DeleteProcThreadAttributeList(self.raw()) };
    }
}

fn initialize_attribute_list(
    attributes: *mut core::ffi::c_void,
    bytes: *mut usize,
) -> Result<(), PlatformError> {
    if unsafe { InitializeProcThreadAttributeList(attributes, 1, 0, bytes) } == 0 {
        return Err(last_error("InitializeProcThreadAttributeList"));
    }
    Ok(())
}

fn update_handle_list(
    attributes: *mut core::ffi::c_void,
    handles: &[Handle],
) -> Result<(), PlatformError> {
    if unsafe {
        UpdateProcThreadAttribute(
            attributes,
            0,
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
            handles.as_ptr().cast(),
            size_of_val(handles),
            ptr::null_mut(),
            ptr::null_mut(),
        )
    } == 0
    {
        unsafe { DeleteProcThreadAttributeList(attributes) };
        return Err(last_error("UpdateProcThreadAttribute"));
    }
    Ok(())
}

pub(super) struct Job(OwnedHandle);

impl Job {
    pub(super) fn create() -> Result<Self, PlatformError> {
        let handle = OwnedHandle::new(
            unsafe { CreateJobObjectW(ptr::null(), ptr::null()) },
            "CreateJobObjectW",
        )?;
        set_kill_on_close(handle.raw())?;
        Ok(Self(handle))
    }

    pub(super) fn assign(&self, process: Handle) -> Result<(), PlatformError> {
        if unsafe { AssignProcessToJobObject(self.0.raw(), process) } == 0 {
            return Err(last_error("AssignProcessToJobObject"));
        }
        Ok(())
    }

    pub(super) fn terminate(&self) -> Result<(), PlatformError> {
        if unsafe { TerminateJobObject(self.0.raw(), 1) } == 0 {
            return Err(last_error("TerminateJobObject"));
        }
        Ok(())
    }
}

fn set_kill_on_close(job: Handle) -> Result<(), PlatformError> {
    let limits = JobObjectExtendedLimitInformation {
        basic_limit_information: JobObjectBasicLimitInformation {
            per_process_user_time_limit: 0,
            per_job_user_time_limit: 0,
            limit_flags: JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            minimum_working_set_size: 0,
            maximum_working_set_size: 0,
            active_process_limit: 0,
            affinity: 0,
            priority_class: 0,
            scheduling_class: 0,
        },
        io_info: IoCounters {
            read_operation_count: 0,
            write_operation_count: 0,
            other_operation_count: 0,
            read_transfer_count: 0,
            write_transfer_count: 0,
            other_transfer_count: 0,
        },
        process_memory_limit: 0,
        job_memory_limit: 0,
        peak_process_memory_used: 0,
        peak_job_memory_used: 0,
    };
    if unsafe {
        SetInformationJobObject(
            job,
            JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
            (&raw const limits).cast(),
            u32::try_from(size_of_val(&limits)).expect("job limit size"),
        )
    } == 0
    {
        return Err(last_error("SetInformationJobObject"));
    }
    Ok(())
}
