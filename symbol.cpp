// symbol.cpp : Defines the entry point for the console application.
//
#include "stdafx.h"

void update_map(boost::python::dict& py_dict) {
  boost::python::list keys = py_dict.keys();
  for (int i = 0; i < len(keys); ++i) {
    boost::python::extract<unsigned int> extracted_key(keys[i]);
    if (!extracted_key.check()) {
      std::cout << "Key invalid, map might be incomplete" << std::endl;
      continue;
    }
    unsigned int                        key           = extracted_key;
    boost::python::extract<std::string> extracted_val(py_dict[key]);
    if (!extracted_val.check()) {
      std::cout << "Value invalid, map might be incomplete" << std::endl;
      continue;
    }
    std::string value = extracted_val;
  }
}

BOOST_PYTHON_MODULE(symbol_ext)
{
    using namespace boost::python;
	
	class_<ModInfo> ("ModInfo", init<>())  
       .def(init<boost::python::list&>())
	   .def("GetModuleName", &ModInfo::GetModuleName)
	   .def("SetRegisterContext", &ModInfo::SetRegisterContext)
	   .def("SetStackRaw", &ModInfo::SetStackRaw)
	   .def("StackWalk", &ModInfo::DoStackWalk);
}


