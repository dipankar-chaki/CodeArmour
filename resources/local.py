import json
import sys
from transformers import RobertaTokenizer, T5ForConditionalGeneration, T5Config, AutoModelForSeq2SeqLM, AutoTokenizer
from transformers import (WEIGHTS_NAME, get_linear_schedule_with_warmup,
                          RobertaConfig, RobertaForSequenceClassification, RobertaTokenizer)
from torch.utils.data import DataLoader, Dataset, SequentialSampler
import torch
import onnxruntime
import numpy as np
import pickle
import os
import torch.nn as nn
from torch.nn import CrossEntropyLoss

path = os.path.dirname(os.path.realpath(__file__))

class RobertaClassificationHead(nn.Module):
    """Head for sentence-level classification tasks."""
    def __init__(self, config):
        super().__init__()
        self.dense = nn.Linear(config.hidden_size, config.hidden_size)
        self.dropout = nn.Dropout(config.hidden_dropout_prob)
        self.out_proj = nn.Linear(config.hidden_size, 2)

    def forward(self, features, **kwargs):
        x = features[:, 0, :]  # take <s> token (equiv. to [CLS])
        x = self.dropout(x)
        x = self.dense(x)
        x = torch.tanh(x)
        x = self.dropout(x)
        x = self.out_proj(x)
        return x
        
class Model(RobertaForSequenceClassification):   
    def __init__(self, encoder, config, tokenizer):
        super(Model, self).__init__(config=config)
        self.encoder = encoder
        self.tokenizer = tokenizer
        self.classifier = RobertaClassificationHead(config)
    
        
    def forward(self, input_embed=None, labels=None, output_attentions=False, input_ids=None):
        if output_attentions:
            if input_ids is not None:
                outputs = self.encoder.roberta(input_ids, attention_mask=input_ids.ne(1), output_attentions=output_attentions)
            else:
                outputs = self.encoder.roberta(inputs_embeds=input_embed, output_attentions=output_attentions)
            attentions = outputs.attentions
            last_hidden_state = outputs.last_hidden_state
            logits = self.classifier(last_hidden_state)
            prob = torch.softmax(logits, dim=-1)
            if labels is not None:
                loss_fct = CrossEntropyLoss()
                loss = loss_fct(logits, labels)
                return loss, prob, attentions
            else:
                return prob, attentions
        else:
            if input_ids is not None:
                outputs = self.encoder.roberta(input_ids, attention_mask=input_ids.ne(1), output_attentions=output_attentions)[0]
            else:
                outputs = self.encoder.roberta(inputs_embeds=input_embed, output_attentions=output_attentions)[0]
            logits = self.classifier(outputs)
            prob = torch.softmax(logits, dim=-1)
            if labels is not None:
                loss_fct = CrossEntropyLoss()
                loss = loss_fct(logits, labels)
                return loss, prob
            else:
                return prob


class InputFeatures(object):
    def __init__(self,input_tokens,input_ids, label):
        self.input_tokens = input_tokens
        self.input_ids = input_ids
        self.label = label

def tokenize_single_function(func, tokenizer, block_size, label):
    
    code_tokens = tokenizer.tokenize(str(func))[:block_size-2]
    source_tokens = [tokenizer.cls_token] + code_tokens + [tokenizer.sep_token]
    source_ids = tokenizer.convert_tokens_to_ids(source_tokens)
    padding_length = block_size - len(source_ids)
    source_ids += [tokenizer.pad_token_id] * padding_length
    return InputFeatures(source_tokens, source_ids, label)


class TextDataset(Dataset):
    def __init__(self, tokenizer, functions, block_size):
        self.examples = []
        for i in range(len(functions)):
            label = 0
            self.examples.append(tokenize_single_function(functions[i], tokenizer, block_size, label))


    def __len__(self):
        return len(self.examples)

    def __getitem__(self, i):       
        return torch.tensor(self.examples[i].input_ids),torch.tensor(0)


def tokenize_all_functions(functions, tokenizer, block_size):
    tokenized_functions = []
    for i in range(len(functions)):
        tokenized_functions.append(tokenize_single_function(functions[i], tokenizer, block_size))
    return tokenized_functions

def test_pred(model, tokenizer, test_dataset, functions, best_threshold=0.5):
    test_sampler = SequentialSampler(test_dataset)
    test_dataloader = DataLoader(test_dataset, sampler=test_sampler, batch_size=1, num_workers=0)
    eval_loss = 0.0
    nb_eval_steps = 0
    model.eval()
    logits=[]
    all_attentions = []  
    input_ids_list = []
    for batch in test_dataloader:
        (inputs_ids, labels) = [x.to(torch.device('cpu')) for x in batch]
        input_ids_list.append(inputs_ids)
        with torch.no_grad():
            lm_loss, logit, attentions = model(input_ids=inputs_ids, labels=labels, output_attentions=True)
            eval_loss += lm_loss.mean().item()
            logits.append(logit.cpu().numpy())
            mean_attentions = []
            for i in range(len(attentions)):
                mean_att = attentions[i].mean(dim=1, keepdim=True)
                mean_attentions.append(mean_att)
            all_attentions.append(mean_attentions)
        nb_eval_steps += 1

    model_input = torch.cat(input_ids_list, dim=0)
    logits = np.concatenate(logits, 0)
    n = len(all_attentions)
    output_attentions = np.stack([np.stack([tensor.numpy() for tensor in inner_list])
    for inner_list in all_attentions])
    output_attentions = output_attentions.squeeze(axis=(2, 3))

    return model_input, logits, output_attentions


def main(code: list, gpu: bool = False) -> dict:
    """Generate vulnerability predictions and line scores.
    Parameters
    ----------
    code : :obj:`list`
        A list of String functions.
    gpu : always False
    Returns
    -------
    :obj:`dict`
        A dictionary with two keys, "batch_vul_pred", "batch_vul_pred_prob", and "batch_line_scores"
        "batch_vul_pred" stores a list of vulnerability prediction: [0, 1, ...] where 0 means non-vulnerable and 1 means vulnerable
        "batch_vul_pred_prob" stores a list of vulnerability prediction probabilities [0.89, 0.75, ...] corresponding to "batch_vul_pred"
        "batch_line_scores" stores line scores as a 2D list [[att_score_0, att_score_1, ..., att_score_n], ...]
    """

    config = RobertaConfig.from_pretrained('microsoft/codebert-base')
    config.num_labels = 1
    ## POSSIBLE VALUES : 1, 2, 3, 4, 6, 8, 12
    config.num_attention_heads = 6
    
    tokenizer = RobertaTokenizer.from_pretrained('microsoft/codebert-base')
    model = RobertaForSequenceClassification.from_pretrained('microsoft/codebert-base', config=config, ignore_mismatched_sizes=True)    
    model = Model(model, config, tokenizer)
    block_size = 512
    model_size = os.path.getsize(path + '/models/12heads_linevul_model.bin')
     
    model.load_state_dict(torch.load(path + '/models/12heads_linevul_model.bin', map_location=torch.device('cpu')), strict=False)
    model.to(torch.device('cpu'))

    test_dataset = TextDataset(tokenizer, code, block_size)

    model_input, prob, attentions = test_pred(model, tokenizer, test_dataset, code, best_threshold=0.5)

    # prepare token for attention line score mapping
    batch_tokens = []
    for mini_batch in model_input.tolist():
        tokens = tokenizer.convert_ids_to_tokens(mini_batch)
        tokens = [token.replace("Ġ", "") for token in tokens]
        tokens = [token.replace("ĉ", "Ċ") for token in tokens]
        batch_tokens.append(tokens)
    batch_att_weight_sum = []
    # access each layer
    for j in range(len(attentions)):
        att_weight_sum = None
        att_of_one_func = attentions[j]
        for i in range(len(attentions[0])):
            layer_attention = att_of_one_func[i]
            # summerize the values of each token dot other tokens
            layer_attention = sum(layer_attention)
            if att_weight_sum is None:
                att_weight_sum = layer_attention
            else:
                att_weight_sum += layer_attention
        # normalize attention score
        att_weight_sum -= att_weight_sum.min()
        att_weight_sum /= att_weight_sum.max()
        batch_att_weight_sum.append(att_weight_sum)
    # batch_line_scores (2D list with shape of [batch size, seq length]): [[att_score_0, att_score_1, ..., att_score_n], ...]
    batch_line_scores = []
    for i in range(len(batch_att_weight_sum)):
        # clean att score for <s> and </s>
        att_weight_sum = clean_special_token_values(batch_att_weight_sum[i], padding=True)
        # attention should be 1D tensor with seq length representing each token's attention value
        word_att_scores = get_word_att_scores(tokens=batch_tokens[i], att_scores=att_weight_sum)
        line_scores = get_all_lines_score(word_att_scores)
        batch_line_scores.append(line_scores)
    # batch_vul_pred (1D list with shape of [batch size]): [pred_1, pred_2, ..., pred_n]
    batch_vul_pred = np.argmax(prob, axis=-1).tolist()
    # batch_vul_pred_prob (1D list with shape of [batch_size]): [prob_1, prob_2, ..., prob_n]
    batch_vul_pred_prob = []
    for i in range(len(prob)):
        batch_vul_pred_prob.append(prob[i][batch_vul_pred[
            i]].item())  # .item() added to prevent 'Object of type float32 is not JSON serializable' error

    return {"batch_vul_pred": batch_vul_pred, "batch_vul_pred_prob": batch_vul_pred_prob,
            "batch_line_scores": batch_line_scores}


def get_word_att_scores(tokens: list, att_scores: list) -> list:
    word_att_scores = []
    for i in range(len(tokens)):
        token, att_score = tokens[i], att_scores[i]
        word_att_scores.append([token, att_score])
    return word_att_scores


def get_all_lines_score(word_att_scores: list):
    # word_att_scores -> [[token, att_value], [token, att_value], ...]
    separator = "Ċ"
    # to return
    all_lines_score = []
    score_sum = 0
    line_idx = 0
    line = ""
    for i in range(len(word_att_scores)):
        # summerize if meet line separator or the last token
        if ((separator in word_att_scores[i][0]) or (i == (len(word_att_scores) - 1))) and score_sum != 0:
            score_sum += word_att_scores[i][1]
            # append line score as float instead of tensor
            all_lines_score.append(score_sum.item())
            score_sum = 0
            line_idx += 1
        # else accumulate score
        elif separator not in word_att_scores[i][0]:
            line += word_att_scores[i][0]
            score_sum += word_att_scores[i][1]
    return all_lines_score


def clean_special_token_values(all_values, padding=False):
    # special token in the beginning of the seq
    all_values[0] = 0
    if padding:
        # get the last non-zero value which represents the att score for </s> token
        idx = [index for index, item in enumerate(all_values) if item != 0][-1]
        all_values[idx] = 0
    else:
        # special token in the end of the seq
        all_values[-1] = 0
    return all_values


def main_cwe(code: list, gpu: bool = False) -> dict:
    """Generate CWE-IDs and CWE Abstract Types Predictions.
    Parameters
    ----------
    code : :obj:`list`
        A list of String functions.
    gpu : always False
    Returns
    -------
    :obj:`dict`
        A dictionary with four keys, "cwe_id", "cwe_id_prob", "cwe_type", "cwe_type_prob"
        "cwe_id" stores a list of CWE-ID predictions: [CWE-787, CWE-119, ...]
        "cwe_id_prob" stores a list of confidence scores of CWE-ID predictions [0.9, 0.7, ...]
        "cwe_type" stores a list of CWE abstract types predictions: ["Base", "Class", ...]
        "cwe_type_prob" stores a list of confidence scores of CWE abstract types predictions [0.9, 0.7, ...]
    """
    provider = ["CPUExecutionProvider"]
    with open(path + "/inference-common/label_map.pkl", "rb") as f:
        cwe_id_map, cwe_type_map = pickle.load(f)
    # load tokenizer
    tokenizer = RobertaTokenizer.from_pretrained(path + "/inference-common/tokenizer")
    tokenizer.add_tokens(["<cls_type>"])
    tokenizer.cls_type_token = "<cls_type>"
    model_input = []
    for c in code:
        code_tokens = tokenizer.tokenize(str(c))[:512 - 3]
        source_tokens = [tokenizer.cls_token] + code_tokens + [tokenizer.cls_type_token] + [tokenizer.sep_token]
        input_ids = tokenizer.convert_tokens_to_ids(source_tokens)
        padding_length = 512 - len(input_ids)
        input_ids += [tokenizer.pad_token_id] * padding_length
        model_input.append(input_ids)
    device = "cpu"
    model_input = torch.tensor(model_input, device=device)
    # onnx runtime session
    ort_session = onnxruntime.InferenceSession(path + "/models/cwe_model.onnx", providers=provider)
    # compute ONNX Runtime output prediction
    ort_inputs = {ort_session.get_inputs()[0].name: to_numpy(model_input)}
    cwe_id_prob, cwe_type_prob = ort_session.run(None, ort_inputs)
    # batch_cwe_id_pred (1D list with shape of [batch size]): [pred_1, pred_2, ..., pred_n]
    batch_cwe_id = np.argmax(cwe_id_prob, axis=-1).tolist()
    # map predicted idx back to CWE-ID
    batch_cwe_id_pred = [cwe_id_map[str(idx)] for idx in batch_cwe_id]
    # batch_cwe_id_pred_prob (1D list with shape of [batch_size]): [prob_1, prob_2, ..., prob_n]
    batch_cwe_id_pred_prob = []
    for i in range(len(cwe_id_prob)):
        batch_cwe_id_pred_prob.append(cwe_id_prob[i][batch_cwe_id[i]].item())
    # batch_cwe_type_pred (1D list with shape of [batch size]): [pred_1, pred_2, ..., pred_n]
    batch_cwe_type = np.argmax(cwe_type_prob, axis=-1).tolist()
    # map predicted idx back to CWE-Type
    batch_cwe_type_pred = [cwe_type_map[str(idx)] for idx in batch_cwe_type]
    # batch_cwe_type_pred_prob (1D list with shape of [batch_size]): [prob_1, prob_2, ..., prob_n]
    batch_cwe_type_pred_prob = []
    for i in range(len(cwe_type_prob)):
        batch_cwe_type_pred_prob.append(cwe_type_prob[i][batch_cwe_type[i]].item())
    return {"cwe_id": batch_cwe_id_pred,
            "cwe_id_prob": batch_cwe_id_pred_prob,
            "cwe_type": batch_cwe_type_pred,
            "cwe_type_prob": batch_cwe_type_pred_prob}


def main_desc(code: list) -> dict:
    """Generate contextual description for vulnerabilities
    Parameters
    ----------
    code : :obj:`list`
        A list of String functions.
    Returns
    -------
    :obj:`dict`
        A dictionary with one key, "description",
        "description" stores a list of generated contextual descriptions
    """
    text = []
    model = AutoModelForSeq2SeqLM.from_pretrained('Salesforce/codet5-base-multi-sum')
    model.load_state_dict(torch.load(path + '/models/NoEmptyRows_description_repair_train_t5.bin', map_location=torch.device('cpu') ))
    tokenizer = AutoTokenizer.from_pretrained('Salesforce/codet5-base-multi-sum')

    model.to('cpu')

    for c in code:
        inputs = tokenizer(c, return_tensors="pt", max_length=512, truncation=True)
        summary_ids = model.generate(inputs['input_ids'], max_length=350, min_length=50, num_beams=3, no_repeat_ngram_size=3, length_penalty=0.5, early_stopping=True)
        text.append(tokenizer.decode(summary_ids[0], skip_special_tokens=True))
    return {"description": text}

def to_numpy(tensor):
    """ get np input for onnx runtime model """
    return tensor.detach().cpu().numpy() if tensor.requires_grad else tensor.cpu().numpy()


if __name__ == "__main__":
    mode = sys.argv[1]
    code = json.loads(sys.stdin.read())
    if mode == "line":
        print(json.dumps(main(code, False)))
    elif mode == "cwe":
        print(json.dumps(main_cwe(code, False)))
    elif mode == "description":
        print(json.dumps(main_desc(code)))