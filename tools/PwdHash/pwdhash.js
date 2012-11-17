/*
 * Remote PwdHash
 * A JavaScript implementation of the PwdHash hashing algorithm.
 * Version 1.0 Copyright (C) Stanford University 2004-2005
 * Contributors: Dan Boneh, Collin Jackson, John Mitchell, Nick Miyake, and Blake Ross
 * Distributed under the BSD License
 * See http://crypto.stanford.edu/PwdHash for more info.
 * Requires the Javascript MD5 library, available here: http://pajhome.org.uk/crypt/md5
 */

var isAdvancedMode = false;

/*
 * Initialize page with default hashing parameters.
 */
function Init() {
  document.hashform.domain.value = "http://www.example.com/";
  document.hashform.sitePassword.value = "";
//  document.hashform.globalPassword.value = "";
  document.hashform.hashedPassword.value = "Press Generate";
  document.hashform.hashedPassword.disabled = true;
}

/*
 * Toggle the mode (advanced or basic)
 */
function ToggleAdvancedMode()
{
  isAdvancedMode = !isAdvancedMode;
  SetMode();
}

/*
 * Show advanced options or hide them, based on isAdvancedMode
 */
function SetMode()
{
  if(isAdvancedMode)
  {
    document.getElementById("theGlobalPassword").style.display = "";
    document.getElementById("theConstraints").style.display = "";
    document.getElementById("theToggleModeLink").innerHTML = "Switch to Basic View";
    document.getElementById("theResetButtonPanel").style.display = "inline";
    document.hashform.clipboardCopyButton.style.display = "inline";
    document.hashform.clipboardClearButton.style.display = "inline";
  }
  else
  {
  }
  TestClipboard();
}

var SPH_kPasswordPrefix = "@@";

/*
 * Returns a conforming hashed password generated from the form's field values.
 */
function Generate()
{
  var uri = document.hashform.domain.value;
  var domain = (new SPH_DomainExtractor()).extractDomain(uri);
  var size = SPH_kPasswordPrefix.length;
  var data = document.hashform.sitePassword.value;
       // + document.hashform.globalPassword.value;
  if (data.substring(0, size) == SPH_kPasswordPrefix)
    data = data.substring(size);
  var result = new String(new SPH_HashedPassword(data, domain));
  return result;
}

/*
 * Display the clipboard panel or the generate panel, depending on the browser
 */ 
function TestClipboard()
{
  try {        
    throw "Clipboard mode disabled";
    if(clipboardData.getData("Text") == null) throw "Clipboard operations disallowed.";    
    document.getElementById("theGeneratePanel").style.display = "none";
    document.getElementById("theClipboardPanel").style.display = "inline";
  } catch(e) {
    document.getElementById("theClipboardPanel").style.display = "none";
    document.getElementById("theGeneratePanel").style.display = "inline";
  }
}

/*
 * Obtain a conforming hashed password and copy it to the clipboard
 */
function GenerateToClipboard()
{
  try
  {
    clipboardData.setData("Text",Generate());
    document.hashform.clipboardCopyButton.disabled = true;
    document.hashform.clipboardClearButton.disabled = false;
  }
  catch(e)
  {
    alert("The script was unable to copy text to your clipboard.");
  }
}

function ClearClipboard()
{
  try
  {
    clipboardData.setData("Text","");
    document.hashform.clipboardCopyButton.disabled = false;
    document.hashform.clipboardClearButton.disabled = true;
  }
  catch(e)
  { 
    alert("The script was unable to clear your clipboard.");
  }
}

/*
 * Obtain a conforming hashed password and put it in the hashed password field
 */
function GenerateToTextField()
{
  document.hashform.hashedPassword.value = Generate();
  document.hashform.hashedPassword.disabled = false;
}

/*
 * Modify the hashed password so that it conforms to the selected constraints
 */    
function ApplyConstraints(candidate)
{
  var len = parseInt(document.hashform.selectMaxLength.value);
  candidate = MaxLength(candidate, len);
  if(document.hashform.checkboxBeginsWithLetter.checked) 
    candidate = BeginsWithLetter(candidate);
  if(document.hashform.checkboxAtLeastOneDigit.checked) 
    candidate = AtLeastOneDigit(candidate);
  if(document.hashform.checkboxNoDigits.checked) 
    candidate = NoDigits(candidate);
  if(document.hashform.checkboxAtLeastOneNonAlphaNumeric.checked) 
    candidate = AtLeastOneNonAlphaNumeric(candidate);
  if(document.hashform.checkboxNoNonAlphaNumeric.checked) 
    candidate = NoNonAlphaNumeric(candidate);
  return candidate;
}

/*
 * To enforce the maximum length constraint, trim characters off the end.
 */
function MaxLength(str, len)
{
  if (str.length > len)
    return str.substring(0,len);
}

/*
 * To enforce the "begins with letter" requirement, see if the first character
 * is a letter. If it's not, replace it with a letter.
 */
function BeginsWithLetter(str)
{
  var replacement;
  if (!(str.charCodeAt(0) <= 'Z'.charCodeAt(0) && 
	str.charCodeAt(0) >= 'A'.charCodeAt(0)) && 
      !(str.charCodeAt(0) <= 'z'.charCodeAt(0) && 
	str.charCodeAt(0) >= 'a'.charCodeAt(0)))
    replacement = String.fromCharCode(str.charCodeAt(0) % 26 + 'a'.charCodeAt(0)) + 
                str.substring(1);
  else replacement = str;
  return replacement;
}

/*
 * To enforce the "at least one digit" constraint, see if the string contains
 * a digit. If it doesn't, replace the second character with a digit.
 */
function AtLeastOneDigit(str)
{
  for(i = 1; i < str.length; i++)
  {
    if(str.charCodeAt(i) <= '9'.charCodeAt(0) && 
       str.charCodeAt(i) >= '0'.charCodeAt(0))
      return str;
  }
  var replacement = str.substring(0,1);
  replacement += String.fromCharCode(str.charCodeAt(1) % 10 + '0'.charCodeAt(0));
  replacement += str.substring(2);
  return replacement;
}

/*
 * To enforce the "no digits" constraint, replace each digit with a letter.
 */
function NoDigits(str)
{
  var replacement = '';
  for(i = 0; i < str.length; i++)
  {
    if(str.charCodeAt(i) <= '9'.charCodeAt(0) &&
       str.charCodeAt(i) >= '0'.charCodeAt(0))
      replacement += String.fromCharCode(str.charCodeAt(i) % 26 + 'a'.charCodeAt(0));
    else replacement += str.charAt(i);
  }
  return replacement;
}

/*
 * To enforce the "at least one alphanumeric" constraint, see if the string
 * contains a nonalphanumeric. If it doesn't, replace the third character with
 * a nonalphanumeric that is valid in base 64 (+ or /).
 */
function AtLeastOneNonAlphaNumeric(str)
{
  for(i = 1; i < str.length; i++)
  {
    if(!(str.charCodeAt(i) <= '9'.charCodeAt(0) && 
         str.charCodeAt(i) >= '0'.charCodeAt(0)) &&
       !(str.charCodeAt(i) <= 'Z'.charCodeAt(0) &&
         str.charCodeAt(i) >= 'A'.charCodeAt(0)) &&
       !(str.charCodeAt(i) <= 'z'.charCodeAt(0) &&
         str.charCodeAt(i) >= 'a'.charCodeAt(0)))
      return str;
  }
  var replacement = str.substring(0,2);
  replacement += (str.charCodeAt(2) % 2) ? '+' : '/';
  replacement += str.substring(3);
  return replacement;
}

/*
 * To enforce the "no nonalphanumeric" constraint, replace each nonalphanumeric
 * with a letter.
 */
function NoNonAlphaNumeric(str)
{
  var replacement = '';
  for(i = 0; i < str.length; i++)
  {
    if(!(str.charCodeAt(i) <= '9'.charCodeAt(0) && 
         str.charCodeAt(i) >= '0'.charCodeAt(0)) &&
       !(str.charCodeAt(i) <= 'Z'.charCodeAt(0) &&
         str.charCodeAt(i) >= 'A'.charCodeAt(0)) &&
       !(str.charCodeAt(i) <= 'z'.charCodeAt(0) &&
         str.charCodeAt(i) >= 'a'.charCodeAt(0)))
      replacement += String.fromCharCode(str.charCodeAt(i) % 26 + 'a'.charCodeAt(0));
    else replacement += str.charAt(i);
  }
  return replacement;
}
